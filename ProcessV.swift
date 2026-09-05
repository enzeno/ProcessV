// ProcessV — a dependency-free macOS 26 menu-bar port monitor.
//
// Build a universal binary by compiling once for arm64 and once for x86_64,
// then combine the two executables with Apple's `lipo` tool. The distributed
// ProcessV.app produced from this source runs natively on either architecture.
//
// ProcessV uses only Apple frameworks and Darwin's native process APIs.

import AppKit
import Darwin
import SwiftUI

// MARK: - Model

struct ServerProcess: Identifiable, Hashable, Sendable {
    let pid: pid_t
    let port: UInt16
    let processName: String
    let executablePath: String
    let ownerUID: uid_t
    let startSeconds: UInt64
    let startMicroseconds: UInt64
    let codexThreadID: String?
    let codexSessionID: String?
    let socketCount: Int

    var id: String { "\(pid):\(port)" }

    var isCodexOwned: Bool { codexThreadID != nil }

    var displayName: String {
        processName.isEmpty ? URL(fileURLWithPath: executablePath).lastPathComponent : processName
    }

    var shortenedThreadID: String? {
        guard let codexThreadID else { return nil }
        return String(codexThreadID.prefix(8))
    }

    var browserURL: URL? {
        URL(string: "http://127.0.0.1:\(port)")
    }

    var codexURL: URL? {
        guard let codexThreadID else { return nil }
        return URL(string: "codex://threads/\(codexThreadID)")
    }

    var isSystemManagedProcess: Bool {
        let systemPrefixes = [
            "/System/",
            "/usr/libexec/",
            "/usr/sbin/"
        ]
        return systemPrefixes.contains { executablePath.hasPrefix($0) }
    }

    var isProtectedProcess: Bool {
        let protectedAppPrefixes = [
            "/Applications/ChatGPT.app/",
            "/Applications/Docker.app/"
        ]
        return isSystemManagedProcess
            || protectedAppPrefixes.contains { executablePath.hasPrefix($0) }
    }

    var canStop: Bool {
        ownerUID == getuid() && pid > 1 && pid != getpid() && !isProtectedProcess
    }
}

struct ScanSnapshot: Sendable {
    let servers: [ServerProcess]
    let inaccessibleProcessCount: Int
}

@MainActor
final class ServerMonitor: ObservableObject {
    @Published private(set) var servers: [ServerProcess] = []
    @Published private(set) var inaccessibleProcessCount = 0
    @Published private(set) var isRefreshing = false
    @Published var pendingStop: ServerProcess?
    @Published var notice: String?

    var codexCount: Int { servers.lazy.filter(\.isCodexOwned).count }

    func refresh(completion: (() -> Void)? = nil) {
        guard !isRefreshing else {
            completion?()
            return
        }
        isRefreshing = true

        Task {
            let snapshot = await Task.detached(priority: .utility) {
                ListenerScanner.scan()
            }.value

            servers = snapshot.servers
            inaccessibleProcessCount = snapshot.inaccessibleProcessCount
            isRefreshing = false
            completion?()
        }
    }

    func requestStop(_ server: ServerProcess) {
        pendingStop = server
    }

    func stopConfirmed() {
        guard let server = pendingStop else { return }
        pendingStop = nil
        stop(server, showSuccessNotice: true)
    }

    func stopImmediately(_ server: ServerProcess) {
        stop(server, showSuccessNotice: false)
    }

    private func stop(_ server: ServerProcess, showSuccessNotice: Bool) {
        guard server.canStop else {
            notice = "ProcessV protects this system-managed process from termination."
            return
        }

        guard ListenerScanner.isSameProcess(server) else {
            notice = "The original process has already exited or its PID was reused. Nothing was stopped."
            refresh()
            return
        }

        if Darwin.kill(server.pid, SIGTERM) == 0 {
            if showSuccessNotice {
                notice = "Sent a graceful stop request to \(server.displayName)."
            }
        } else {
            notice = "Could not stop \(server.displayName): \(String(cString: strerror(errno)))."
        }

        Task {
            try? await Task.sleep(for: .milliseconds(700))
            refresh()
        }
    }
}

// MARK: - Native listener discovery

private enum ListenerScanner {
    private struct ProcessDetails {
        let name: String
        let path: String
        let uid: uid_t
        let parentPID: pid_t
        let startSeconds: UInt64
        let startMicroseconds: UInt64
    }

    private struct CodexIdentity {
        let threadID: String?
        let sessionID: String?

        var isEmpty: Bool { threadID == nil && sessionID == nil }
    }

    private struct ProcessPort: Hashable {
        let pid: pid_t
        let port: UInt16
    }

    static func scan() -> ScanSnapshot {
        let pids = allProcessIDs()
        var socketsByProcessAndPort: [ProcessPort: Int] = [:]
        var inaccessible = 0

        for pid in pids where pid > 0 {
            let result = listeningPorts(pid: pid)
            if result.inaccessible {
                inaccessible += 1
            }
            for port in result.ports {
                socketsByProcessAndPort[ProcessPort(pid: pid, port: port), default: 0] += 1
            }
        }

        var detailCache: [pid_t: ProcessDetails] = [:]
        var identityCache: [pid_t: CodexIdentity] = [:]
        var servers: [ServerProcess] = []

        for (key, socketCount) in socketsByProcessAndPort {
            guard let details = processDetails(pid: key.pid) else { continue }
            detailCache[key.pid] = details

            let identity = codexIdentity(
                pid: key.pid,
                detailCache: &detailCache,
                identityCache: &identityCache
            )

            servers.append(
                ServerProcess(
                    pid: key.pid,
                    port: key.port,
                    processName: details.name,
                    executablePath: details.path,
                    ownerUID: details.uid,
                    startSeconds: details.startSeconds,
                    startMicroseconds: details.startMicroseconds,
                    codexThreadID: identity.threadID,
                    codexSessionID: identity.sessionID,
                    socketCount: socketCount
                )
            )
        }

        servers.removeAll { $0.isSystemManagedProcess }

        servers.sort {
            if $0.startSeconds != $1.startSeconds {
                return $0.startSeconds > $1.startSeconds
            }
            if $0.startMicroseconds != $1.startMicroseconds {
                return $0.startMicroseconds > $1.startMicroseconds
            }
            if $0.port != $1.port { return $0.port < $1.port }
            if $0.displayName != $1.displayName {
                return $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
            }
            return $0.pid < $1.pid
        }

        return ScanSnapshot(servers: servers, inaccessibleProcessCount: inaccessible)
    }

    static func isSameProcess(_ server: ServerProcess) -> Bool {
        guard let details = processDetails(pid: server.pid) else { return false }
        return details.startSeconds == server.startSeconds
            && details.startMicroseconds == server.startMicroseconds
            && details.uid == server.ownerUID
    }

    private static func allProcessIDs() -> [pid_t] {
        let estimatedCount = max(proc_listallpids(nil, 0), 64)
        var pids = [pid_t](repeating: 0, count: Int(estimatedCount) + 64)
        let count = pids.withUnsafeMutableBytes { bytes in
            proc_listallpids(bytes.baseAddress, Int32(bytes.count))
        }
        guard count > 0 else { return [] }
        return Array(pids.prefix(Int(count))).filter { $0 > 0 }
    }

    private static func listeningPorts(pid: pid_t) -> (ports: [UInt16], inaccessible: Bool) {
        let requiredBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard requiredBytes > 0 else {
            return ([], errno == EPERM || errno == EACCES)
        }

        let stride = MemoryLayout<proc_fdinfo>.stride
        var descriptors = [proc_fdinfo](
            repeating: proc_fdinfo(),
            count: Int(requiredBytes) / stride + 8
        )

        let bytesRead = descriptors.withUnsafeMutableBytes { bytes in
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, bytes.baseAddress, Int32(bytes.count))
        }
        guard bytesRead > 0 else {
            return ([], errno == EPERM || errno == EACCES)
        }

        var ports: [UInt16] = []
        let descriptorCount = min(descriptors.count, Int(bytesRead) / stride)

        for descriptor in descriptors.prefix(descriptorCount)
        where descriptor.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            var socket = socket_fdinfo()
            let socketBytes = withUnsafeMutablePointer(to: &socket) { pointer in
                proc_pidfdinfo(
                    pid,
                    descriptor.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    pointer,
                    Int32(MemoryLayout<socket_fdinfo>.size)
                )
            }

            guard socketBytes == Int32(MemoryLayout<socket_fdinfo>.size) else { continue }
            guard socket.psi.soi_family == AF_INET || socket.psi.soi_family == AF_INET6 else { continue }
            guard socket.psi.soi_type == SOCK_STREAM else { continue }
            guard socket.psi.soi_protocol == IPPROTO_TCP else { continue }
            guard socket.psi.soi_kind == SOCKINFO_TCP else { continue }
            guard socket.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN else { continue }

            let networkPort = UInt16(truncatingIfNeeded: socket.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport)
            let hostPort = UInt16(bigEndian: networkPort)
            if hostPort > 0 {
                ports.append(hostPort)
            }
        }

        return (ports, false)
    }

    private static func processDetails(pid: pid_t) -> ProcessDetails? {
        var info = proc_bsdinfo()
        let bytes = withUnsafeMutablePointer(to: &info) { pointer in
            proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                pointer,
                Int32(MemoryLayout<proc_bsdinfo>.size)
            )
        }
        guard bytes == Int32(MemoryLayout<proc_bsdinfo>.size) else { return nil }

        var nameBuffer = [CChar](repeating: 0, count: 1_024)
        let nameLength = nameBuffer.withUnsafeMutableBytes { bytes in
            proc_name(pid, bytes.baseAddress, UInt32(bytes.count))
        }
        let name = nameLength > 0 ? String(cString: nameBuffer) : ""

        // PROC_PIDPATHINFO_MAXSIZE is a C expression macro and is not imported
        // into Swift, so use its SDK-defined value of 4 * MAXPATHLEN.
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN * 4))
        let pathLength = pathBuffer.withUnsafeMutableBytes { bytes in
            proc_pidpath(pid, bytes.baseAddress, UInt32(bytes.count))
        }
        let path = pathLength > 0 ? String(cString: pathBuffer) : name

        return ProcessDetails(
            name: name,
            path: path,
            uid: info.pbi_uid,
            parentPID: pid_t(info.pbi_ppid),
            startSeconds: info.pbi_start_tvsec,
            startMicroseconds: info.pbi_start_tvusec
        )
    }

    private static func codexIdentity(
        pid: pid_t,
        detailCache: inout [pid_t: ProcessDetails],
        identityCache: inout [pid_t: CodexIdentity]
    ) -> CodexIdentity {
        if let cached = identityCache[pid] { return cached }

        var currentPID = pid
        var visited = Set<pid_t>()
        var lineage: [pid_t] = []

        for _ in 0..<16 {
            guard currentPID > 1, !visited.contains(currentPID) else { break }
            visited.insert(currentPID)
            lineage.append(currentPID)

            if let cached = identityCache[currentPID], !cached.isEmpty {
                for lineagePID in lineage { identityCache[lineagePID] = cached }
                return cached
            }

            let directIdentity = codexEnvironment(pid: currentPID)
            if !directIdentity.isEmpty {
                for lineagePID in lineage { identityCache[lineagePID] = directIdentity }
                return directIdentity
            }

            let details: ProcessDetails
            if let cached = detailCache[currentPID] {
                details = cached
            } else if let discovered = processDetails(pid: currentPID) {
                detailCache[currentPID] = discovered
                details = discovered
            } else {
                break
            }

            currentPID = details.parentPID
        }

        let empty = CodexIdentity(threadID: nil, sessionID: nil)
        for lineagePID in lineage { identityCache[lineagePID] = empty }
        return empty
    }

    private static func codexEnvironment(pid: pid_t) -> CodexIdentity {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var byteCount = 0

        guard sysctl(&mib, u_int(mib.count), nil, &byteCount, nil, 0) == 0,
              byteCount > MemoryLayout<Int32>.size else {
            return CodexIdentity(threadID: nil, sessionID: nil)
        }

        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard sysctl(&mib, u_int(mib.count), &bytes, &byteCount, nil, 0) == 0 else {
            return CodexIdentity(threadID: nil, sessionID: nil)
        }

        let argc = bytes.withUnsafeBytes { raw -> Int32 in
            raw.load(as: Int32.self)
        }
        guard argc >= 0 else {
            return CodexIdentity(threadID: nil, sessionID: nil)
        }

        var index = MemoryLayout<Int32>.size

        // Skip the executable path and the padding before argv[0].
        while index < byteCount && bytes[index] != 0 { index += 1 }
        while index < byteCount && bytes[index] == 0 { index += 1 }

        // Skip argc argument strings. Environment strings follow argv.
        for _ in 0..<Int(argc) {
            while index < byteCount && bytes[index] != 0 { index += 1 }
            while index < byteCount && bytes[index] == 0 { index += 1 }
        }

        var threadID: String?
        var sessionID: String?

        while index < byteCount {
            let start = index
            while index < byteCount && bytes[index] != 0 { index += 1 }

            if index > start,
               let string = String(bytes: bytes[start..<index], encoding: .utf8) {
                if string.hasPrefix("CODEX_THREAD_ID=") {
                    threadID = String(string.dropFirst("CODEX_THREAD_ID=".count)).nilIfEmpty
                } else if string.hasPrefix("CODEX_SESSION_ID=") {
                    sessionID = String(string.dropFirst("CODEX_SESSION_ID=".count)).nilIfEmpty
                }
            }

            while index < byteCount && bytes[index] == 0 { index += 1 }
            if threadID != nil && sessionID != nil { break }
        }

        return CodexIdentity(threadID: threadID, sessionID: sessionID)
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

// MARK: - Liquid Glass interface

struct ProcessVPanel: View {
    @ObservedObject var monitor: ServerMonitor
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(summaryText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 16)

            Divider()
                .padding(.horizontal, 16)

            if monitor.servers.isEmpty {
                emptyState
            } else {
                serverList
            }
        }
        .frame(width: 430, height: panelHeight)
        .background(panelBackground)
        .alert("Stop server?", isPresented: stopAlertBinding, presenting: monitor.pendingStop) { server in
            Button("Cancel", role: .cancel) {
                monitor.pendingStop = nil
            }
            Button("Stop Process", role: .destructive) {
                monitor.stopConfirmed()
            }
        } message: { server in
            Text(verbatim: "\(server.displayName) (PID \(server.pid)) owns port \(server.port). Stopping it may also close other ports owned by the same process.")
        }
        .alert("ProcessV", isPresented: noticeBinding) {
            Button("OK") {
                monitor.notice = nil
            }
        } message: {
            Text(monitor.notice ?? "")
        }
    }

    private var stopAlertBinding: Binding<Bool> {
        Binding(
            get: { monitor.pendingStop != nil },
            set: { if !$0 { monitor.pendingStop = nil } }
        )
    }

    private var noticeBinding: Binding<Bool> {
        Binding(
            get: { monitor.notice != nil },
            set: { if !$0 { monitor.notice = nil } }
        )
    }

    private var summaryText: String {
        let portWord = monitor.servers.count == 1 ? "port" : "ports"
        if monitor.codexCount == 0 {
            return "\(monitor.servers.count) listening \(portWord)"
        }
        return "\(monitor.servers.count) listening · \(monitor.codexCount) from Codex"
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "network.slash")
                .font(.system(size: 28, weight: .light))
                .foregroundStyle(.secondary)
            Text("No listening TCP servers")
                .font(.headline)
            Text("Reopen the menu to scan again.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 140)
        .padding()
    }

    private var serverList: some View {
        ScrollView {
            GlassEffectContainer(spacing: 10) {
                LazyVStack(spacing: 10) {
                    ForEach(monitor.servers) { server in
                        ServerRow(server: server, monitor: monitor, openURL: openURL)
                    }
                }
                .padding(14)
            }
        }
        .frame(maxHeight: .infinity)
    }

    private var panelHeight: CGFloat {
        let content = CGFloat(max(monitor.servers.count, 1)) * 76
        return min(560, max(160, content + 56))
    }

    @ViewBuilder
    private var panelBackground: some View {
        ZStack {
            Color.clear
            LinearGradient(
                colors: [
                    Color.accentColor.opacity(0.08),
                    Color.clear,
                    Color.cyan.opacity(0.04)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        }
    }
}

private struct ServerRow: View {
    let server: ServerProcess
    @ObservedObject var monitor: ServerMonitor
    let openURL: OpenURLAction
    @State private var dragOffset: CGFloat = 0

    private let maximumReveal: CGFloat = 118
    private let commitDistance: CGFloat = 82

    var body: some View {
        ZStack {
            swipeActionBackground
            rowContent
                .background(
                    Color(nsColor: .controlBackgroundColor),
                    in: RoundedRectangle(cornerRadius: 16, style: .continuous)
                )
                .overlay {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .stroke(Color.primary.opacity(0.09), lineWidth: 0.75)
                }
                .compositingGroup()
                .offset(x: dragOffset)
                .allowsHitTesting(dragOffset == 0)
        }
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .contentShape(.rect)
        .simultaneousGesture(swipeGesture)
        .contextMenu {
            Button {
                if let url = server.browserURL { openURL(url) }
            } label: {
                Text(verbatim: "Open localhost:\(server.port)")
            }

            if let codexURL = server.codexURL {
                Button("Open Codex Task") {
                    openURL(codexURL)
                }
            }

            if server.canStop {
                Divider()
                Button("Stop Process…", role: .destructive) {
                    monitor.requestStop(server)
                }
            }
        }
        .accessibilityAction(named: "Stop process immediately") {
            if server.canStop { monitor.stopImmediately(server) }
        }
        .accessibilityAction(named: "Open originating Codex task") {
            if let codexURL = server.codexURL { openURL(codexURL) }
        }
    }

    private var rowContent: some View {
        HStack(spacing: 12) {
            portBadge

            VStack(alignment: .leading, spacing: 4) {
                Text(server.displayName)
                    .font(.system(.body, design: .rounded, weight: .semibold))
                    .lineLimit(1)

                HStack(spacing: 7) {
                    Text(verbatim: "PID \(server.pid)")
                    Text("TCP")
                    if server.socketCount > 1 {
                        Text("IPv4 + IPv6")
                    }
                }
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }

            Spacer(minLength: 4)

            HStack(spacing: 8) {
                if server.isCodexOwned, let codexURL = server.codexURL {
                    Button {
                        openURL(codexURL)
                    } label: {
                        ChatGPTMark(size: 17)
                            .frame(width: 32, height: 32)
                    }
                    .help("Open Codex task \(server.shortenedThreadID ?? "")")
                    .accessibilityLabel("Open originating Codex task")
                }

                Button {
                    if let url = server.browserURL {
                        openURL(url)
                    }
                } label: {
                    Image(systemName: "safari")
                        .frame(width: 32, height: 32)
                }
                .help(Text(verbatim: "Open localhost:\(server.port)"))

                if server.canStop {
                    Button {
                        monitor.requestStop(server)
                    } label: {
                        Image(systemName: "stop.fill")
                            .foregroundStyle(.red)
                            .frame(width: 32, height: 32)
                    }
                    .help("Stop \(server.displayName)")
                }
            }
            .buttonStyle(.plain)
            .controlSize(.regular)
        }
        .padding(12)
    }

    private var swipeActionBackground: some View {
        ZStack {
            HStack(spacing: 8) {
                ChatGPTMark(size: 18, color: .white)
                Text("Open Codex")
                    .font(.caption.weight(.semibold))
                Spacer()
            }
            .foregroundStyle(.white)
            .padding(.leading, 18)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color.blue)
            .opacity(dragOffset > 0 && server.codexURL != nil ? revealOpacity : 0)

            HStack(spacing: 8) {
                Spacer()
                Text("Stop")
                    .font(.caption.weight(.semibold))
                Image(systemName: "stop.fill")
            }
            .foregroundStyle(.white)
            .padding(.trailing, 18)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color.red)
            .opacity(dragOffset < 0 && server.canStop ? revealOpacity : 0)
        }
    }

    private var revealOpacity: Double {
        min(Double(abs(dragOffset) / 42), 1)
    }

    private var swipeGesture: some Gesture {
        DragGesture(minimumDistance: 10)
            .onChanged { value in
                let horizontal = value.translation.width
                let vertical = value.translation.height
                guard abs(horizontal) > abs(vertical) else { return }

                let permitted: CGFloat
                if horizontal < 0, server.canStop {
                    permitted = max(horizontal, -maximumReveal)
                } else if horizontal > 0, server.codexURL != nil {
                    permitted = min(horizontal, maximumReveal)
                } else {
                    permitted = 0
                }

                dragOffset = permitted
            }
            .onEnded { value in
                let projected = abs(value.predictedEndTranslation.width) > abs(value.translation.width)
                    ? value.predictedEndTranslation.width
                    : value.translation.width
                let shouldStop = dragOffset < 0 && projected <= -commitDistance && server.canStop
                let shouldOpenCodex = dragOffset > 0 && projected >= commitDistance && server.codexURL != nil

                if shouldStop {
                    performCommitHaptic()
                    commitSwipe(toward: -maximumReveal) {
                        monitor.stopImmediately(server)
                    }
                } else if shouldOpenCodex, let codexURL = server.codexURL {
                    performCommitHaptic()
                    commitSwipe(toward: maximumReveal) {
                        openURL(codexURL)
                    }
                } else {
                    withAnimation(.snappy(duration: 0.24)) {
                        dragOffset = 0
                    }
                }
            }
    }

    private func performCommitHaptic() {
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .now)
    }

    private func commitSwipe(toward destination: CGFloat, action: @escaping () -> Void) {
        withAnimation(.snappy(duration: 0.16)) {
            dragOffset = destination
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.12) {
            action()
            withAnimation(.snappy(duration: 0.2)) {
                dragOffset = 0
            }
        }
    }

    private var portBadge: some View {
        VStack(spacing: 1) {
            Text(verbatim: ":\(server.port)")
                .font(.system(.callout, design: .monospaced, weight: .bold))
            Circle()
                .fill(server.isCodexOwned ? Color.green : Color.secondary.opacity(0.65))
                .frame(width: 5, height: 5)
        }
        .frame(width: 62, height: 42)
        .background(Color.primary.opacity(0.055), in: RoundedRectangle(cornerRadius: 11, style: .continuous))
    }
}

private struct ChatGPTMark: View {
    let size: CGFloat
    var color: Color? = nil
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        ChatGPTLogoShape()
            .fill(color ?? (colorScheme == .dark ? Color.white : Color.black))
            .padding(size * 0.08)
        .frame(width: size, height: size)
        .contentShape(.circle)
    }
}

/// The official ChatGPT mark's 320×320 SVG path, embedded as geometry so the
/// app stays a single source file with no runtime assets or dependencies.
private struct ChatGPTLogoShape: Shape {
    private static let pathData = """
    m297.06 130.97c7.26-21.79 4.76-45.66-6.85-65.48-17.46-30.4-52.56-46.04-86.84-38.68-15.25-17.18-37.16-26.95-60.13-26.81-35.04-.08-66.13 22.48-76.91 55.82-22.51 4.61-41.94 18.7-53.31 38.67-17.59 30.32-13.58 68.54 9.92 94.54-7.26 21.79-4.76 45.66 6.85 65.48 17.46 30.4 52.56 46.04 86.84 38.68 15.24 17.18 37.16 26.95 60.13 26.8 35.06.09 66.16-22.49 76.94-55.86 22.51-4.61 41.94-18.7 53.31-38.67 17.57-30.32 13.55-68.51-9.94-94.51zm-120.28 168.11c-14.03.02-27.62-4.89-38.39-13.88.49-.26 1.34-.73 1.89-1.07l63.72-36.8c3.26-1.85 5.26-5.32 5.24-9.07v-89.83l26.93 15.55c.29.14.48.42.52.74v74.39c-.04 33.08-26.83 59.9-59.91 59.97zm-128.84-55.03c-7.03-12.14-9.56-26.37-7.15-40.18.47.28 1.3.79 1.89 1.13l63.72 36.8c3.23 1.89 7.23 1.89 10.47 0l77.79-44.92v31.1c.02.32-.13.63-.38.83l-64.41 37.19c-28.69 16.52-65.33 6.7-81.92-21.95zm-16.77-139.09c7-12.16 18.05-21.46 31.21-26.29 0 .55-.03 1.52-.03 2.2v73.61c-.02 3.74 1.98 7.21 5.23 9.06l77.79 44.91-26.93 15.55c-.27.18-.61.21-.91.08l-64.42-37.22c-28.63-16.58-38.45-53.21-21.95-81.89zm221.26 51.49-77.79-44.92 26.93-15.54c.27-.18.61-.21.91-.08l64.42 37.19c28.68 16.57 38.51 53.26 21.94 81.94-7.01 12.14-18.05 21.44-31.2 26.28v-75.81c.03-3.74-1.96-7.2-5.2-9.06zm26.8-40.34c-.47-.29-1.3-.79-1.89-1.13l-63.72-36.8c-3.23-1.89-7.23-1.89-10.47 0l-77.79 44.92v-31.1c-.02-.32.13-.63.38-.83l64.41-37.16c28.69-16.55 65.37-6.7 81.91 22 6.99 12.12 9.52 26.31 7.15 40.1zm-168.51 55.43-26.94-15.55c-.29-.14-.48-.42-.52-.74v-74.39c.02-33.12 26.89-59.96 60.01-59.94 14.01 0 27.57 4.92 38.34 13.88-.49.26-1.33.73-1.89 1.07l-63.72 36.8c-3.26 1.85-5.26 5.31-5.24 9.06l-.04 89.79zm14.63-31.54 34.65-20.01 34.65 20v40.01l-34.65 20-34.65-20z
    """

    private static let logoPath: Path = SVGPathParser.parse(pathData)

    func path(in rect: CGRect) -> Path {
        Self.logoPath.applying(
            CGAffineTransform(
                scaleX: rect.width / 320,
                y: rect.height / 320
            ).translatedBy(x: rect.minX, y: rect.minY)
        )
    }
}

/// A deliberately tiny parser for the SVG commands used by the embedded mark.
private enum SVGPathParser {
    static func parse(_ source: String) -> Path {
        var parser = Parser(source)
        var path = Path()
        var point = CGPoint.zero
        var subpathStart = CGPoint.zero
        var command: Character?

        while !parser.isAtEnd {
            if let next = parser.readCommand() { command = next }
            guard let command else { break }

            switch command {
            case "M", "m":
                var first = true
                while let x = parser.readNumber(), let y = parser.readNumber() {
                    let destination = command == "m"
                        ? CGPoint(x: point.x + x, y: point.y + y)
                        : CGPoint(x: x, y: y)
                    if first {
                        path.move(to: destination)
                        subpathStart = destination
                        first = false
                    } else {
                        path.addLine(to: destination)
                    }
                    point = destination
                    if parser.nextIsCommand { break }
                }
            case "L", "l":
                while let x = parser.readNumber(), let y = parser.readNumber() {
                    point = command == "l"
                        ? CGPoint(x: point.x + x, y: point.y + y)
                        : CGPoint(x: x, y: y)
                    path.addLine(to: point)
                    if parser.nextIsCommand { break }
                }
            case "H", "h":
                while let x = parser.readNumber() {
                    point.x = command == "h" ? point.x + x : x
                    path.addLine(to: point)
                    if parser.nextIsCommand { break }
                }
            case "V", "v":
                while let y = parser.readNumber() {
                    point.y = command == "v" ? point.y + y : y
                    path.addLine(to: point)
                    if parser.nextIsCommand { break }
                }
            case "C", "c":
                while let x1 = parser.readNumber(), let y1 = parser.readNumber(),
                      let x2 = parser.readNumber(), let y2 = parser.readNumber(),
                      let x = parser.readNumber(), let y = parser.readNumber() {
                    let relative = command == "c"
                    let control1 = CGPoint(
                        x: relative ? point.x + x1 : x1,
                        y: relative ? point.y + y1 : y1
                    )
                    let control2 = CGPoint(
                        x: relative ? point.x + x2 : x2,
                        y: relative ? point.y + y2 : y2
                    )
                    let destination = CGPoint(
                        x: relative ? point.x + x : x,
                        y: relative ? point.y + y : y
                    )
                    path.addCurve(to: destination, control1: control1, control2: control2)
                    point = destination
                    if parser.nextIsCommand { break }
                }
            case "Z", "z":
                path.closeSubpath()
                point = subpathStart
            default:
                return path
            }
        }

        return path
    }

    private struct Parser {
        private let characters: [Character]
        private var index = 0

        init(_ source: String) {
            characters = Array(source)
        }

        var isAtEnd: Bool {
            skipSeparatorsIndex() >= characters.count
        }

        var nextIsCommand: Bool {
            let next = skipSeparatorsIndex()
            return next < characters.count && characters[next].isLetter
        }

        mutating func readCommand() -> Character? {
            skipSeparators()
            guard index < characters.count, characters[index].isLetter else { return nil }
            defer { index += 1 }
            return characters[index]
        }

        mutating func readNumber() -> CGFloat? {
            skipSeparators()
            guard index < characters.count, !characters[index].isLetter else { return nil }

            let start = index
            if characters[index] == "+" || characters[index] == "-" { index += 1 }
            while index < characters.count, characters[index].isNumber { index += 1 }
            if index < characters.count, characters[index] == "." {
                index += 1
                while index < characters.count, characters[index].isNumber { index += 1 }
            }
            if index < characters.count, characters[index] == "e" || characters[index] == "E" {
                index += 1
                if index < characters.count, characters[index] == "+" || characters[index] == "-" { index += 1 }
                while index < characters.count, characters[index].isNumber { index += 1 }
            }

            return Double(String(characters[start..<index])).map { CGFloat($0) }
        }

        private mutating func skipSeparators() {
            index = skipSeparatorsIndex()
        }

        private func skipSeparatorsIndex() -> Int {
            var next = index
            while next < characters.count,
                  characters[next].isWhitespace || characters[next] == "," {
                next += 1
            }
            return next
        }
    }
}

// MARK: - App

@MainActor
private final class ProcessVAppDelegate: NSObject, NSApplicationDelegate {
    private let monitor = ServerMonitor()
    private let popover = NSPopover()
    private var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        installStatusItem()
    }

    func applicationDidResignActive(_ notification: Notification) {
        if popover.isShown {
            popover.performClose(nil)
        }
    }

    func installStatusItem() {
        guard statusItem == nil else { return }
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem = item

        if let button = item.button {
            let image = NSImage(systemSymbolName: "server.rack", accessibilityDescription: "ProcessV")
            image?.isTemplate = true
            button.image = image
            button.toolTip = "ProcessV"
            button.target = self
            button.action = #selector(statusItemClicked(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }

        // SwiftUI alerts are separate child windows. A transient popover closes
        // as soon as that alert receives a click, making its buttons unusable.
        // Keep dismissal under the status item's control instead.
        popover.behavior = .applicationDefined
        popover.animates = true
        popover.contentViewController = NSHostingController(
            rootView: ProcessVPanel(monitor: monitor)
        )
    }

    @objc private func statusItemClicked(_ sender: NSStatusBarButton) {
        if NSApp.currentEvent?.type == .rightMouseUp {
            showContextMenu(relativeTo: sender)
        } else if popover.isShown {
            popover.performClose(nil)
        } else {
            monitor.refresh { [weak self, weak sender] in
                DispatchQueue.main.async {
                    guard let self, let sender else { return }
                    self.showPopover(relativeTo: sender)
                }
            }
        }
    }

    private func showPopover(relativeTo button: NSStatusBarButton) {
        let rowHeight: CGFloat = 76
        let contentHeight = CGFloat(max(monitor.servers.count, 1)) * rowHeight
        popover.contentSize = NSSize(
            width: 430,
            height: min(560, max(160, contentHeight + 56))
        )
        NSApp.activate(ignoringOtherApps: true)
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        DispatchQueue.main.async { [weak self] in
            guard let window = self?.popover.contentViewController?.view.window else { return }
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
        }
    }

    private func showContextMenu(relativeTo button: NSStatusBarButton) {
        let menu = NSMenu()
        let quit = NSMenuItem(
            title: "Quit ProcessV",
            action: #selector(quitProcessV),
            keyEquivalent: "q"
        )
        quit.target = self
        menu.addItem(quit)
        menu.popUp(
            positioning: nil,
            at: NSPoint(x: 0, y: button.bounds.minY - 4),
            in: button
        )
    }

    @objc private func quitProcessV() {
        NSApplication.shared.terminate(nil)
    }
}

@MainActor
@objc(ProcessVApplication)
private final class ProcessVApplication: NSApplication {
    private let processVDelegate = ProcessVAppDelegate()

    override init() {
        super.init()
        delegate = processVDelegate
        setActivationPolicy(.accessory)
    }

    override func finishLaunching() {
        super.finishLaunching()
        processVDelegate.installStatusItem()
    }

    required init?(coder: NSCoder) {
        fatalError("ProcessV does not support NSCoding")
    }
}

@main
struct ProcessVApp {
    @MainActor
    static func main() {
        if CommandLine.arguments.contains("--scan-once") {
            let snapshot = ListenerScanner.scan()
            for server in snapshot.servers {
                let codex = server.codexThreadID.map { " codex=\($0)" } ?? ""
                print(":\(server.port) pid=\(server.pid) \(server.displayName)\(codex)")
            }
            Darwin.exit(EXIT_SUCCESS)
        }

        _ = NSApplicationMain(CommandLine.argc, CommandLine.unsafeArgv)
    }
}
