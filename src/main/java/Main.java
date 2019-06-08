import ssh2.libssh2;
import ssh2.libssh2_h;

import java.awt.*;
import java.foreign.*;
import java.foreign.memory.Callback;
import java.foreign.memory.Pointer;
import java.io.Console;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Supplier;

import static java.foreign.memory.Pointer.ofNull;

/**
 * A demo Java SSH2 client using JDK13 <a href="https://openjdk.java.net/projects/panama/">Project Panama</a>.
 * <p>
 * Based on libSSH2 <a href="https://www.libssh2.org/examples/">sample source code</a>.
 */
public class Main {

    private static final String RT_SHELL = "shell";
    private static final String TERMINAL_TYPE = "ansi";

    private static String hostname, username;
    private static int port, connType;

    private static Pointer<libssh2._LIBSSH2_SESSION> ptrSession = Pointer.ofNull();
    private static Pointer<libssh2._LIBSSH2_CHANNEL> ptrChannel = Pointer.ofNull();

    public static void main(String[] args) {
        parseArgs(args);

        int rc = libssh2_h.libssh2_init(0);
        if (rc != 0) {
            System.err.println(String.format("Could not init libssh2: %d", rc));
            return;
        }


        try (Scope scope = Scope.globalScope().fork()) {
            try {
                System.out.println(String.format("Connecting to %s:%d...", hostname, port));

                ptrSession = libssh2_h.libssh2_session_init_ex(Callback.ofNull(), Callback.ofNull(),
                        Callback.ofNull(), ofNull());
                final int fd = (int) connectFd(hostname, port);

                nio(() -> libssh2_h.libssh2_session_handshake(ptrSession, fd), "SSH handshake failed!");

                String fingerprint = Pointer.toString(libssh2_h.libssh2_hostkey_hash(ptrSession,
                        libssh2_h.LIBSSH2_HOSTKEY_HASH_SHA1));
                System.out.println(String.format("SHA1 Fingerprint: %s", bytesToHex(
                        fingerprint.getBytes(StandardCharsets.US_ASCII))));

                final String auth = Pointer.toString(libssh2_h.libssh2_userauth_list(ptrSession,
                        scope.allocateCString(username), username.length()));
                System.out.println("Authentications: " + auth);

                if (auth.contains("password") && connType == 1) {
                    Console console = System.console();
                    StringBuilder sb = new StringBuilder();
                    sb.append(console.readPassword("%s's password: ", hostname));

                    if (libssh2_h.libssh2_userauth_password_ex(ptrSession,
                            scope.allocateCString(username), username.length(),
                            scope.allocateCString(sb.toString()), sb.length(), Callback.ofNull()) != 0) {
                        throw new RuntimeException("Authentication by password failed!");
                    } else {
                        System.out.println("Authentication by password successful.");
                    }
                } else if (auth.contains("publickey") && connType == 2) {
                    // TODO configurable pbk paths?
                    if (libssh2_h.libssh2_userauth_publickey_fromfile_ex(ptrSession,
                            scope.allocateCString(username), username.length(),
                            scope.allocateCString("~/.ssh/id_rsa.pub"), scope.allocateCString("~/.ssh/id_rsa"),
                            scope.allocateCString("")) != 0) {
                        throw new RuntimeException("Authentication by public key failed!");
                    } else {
                        System.out.println("Authentication by public key successful.");
                    }
                } else {
                    throw new RuntimeException("No known authentication type supported!");
                }

                final String channelType = "session";
                ptrChannel = libssh2_h.libssh2_channel_open_ex(ptrSession,
                        scope.allocateCString(channelType), channelType.length(),
                        libssh2_h.LIBSSH2_CHANNEL_WINDOW_DEFAULT,
                        libssh2_h.LIBSSH2_CHANNEL_PACKET_DEFAULT,
                        ofNull(), 0);
                if (ptrChannel.isNull()) {
                    throw new RuntimeException("Could not open a session!");
                }

                nio(() -> libssh2_h.libssh2_channel_request_pty_ex(ptrChannel, scope.allocateCString(TERMINAL_TYPE),
                        TERMINAL_TYPE.length(), Pointer.ofNull(), 0,
                        libssh2_h.LIBSSH2_TERM_WIDTH, libssh2_h.LIBSSH2_TERM_HEIGHT,
                        libssh2_h.LIBSSH2_TERM_WIDTH_PX, libssh2_h.LIBSSH2_TERM_HEIGHT_PX), "Failed requesting pty!");

                nio(() -> libssh2_h.libssh2_channel_process_startup(ptrChannel,
                        scope.allocateCString(RT_SHELL), RT_SHELL.length(), ofNull(), 0), "Unable to request shell on pty!");

                // disable blocking mode
                libssh2_h.libssh2_channel_set_blocking(ptrChannel, 0);
                libssh2_h.libssh2_session_set_blocking(ptrSession, 0);

                final int BUFSIZE = 32000;
                long read = -1, write = -1, active = 0;
                boolean quit = false;

                libssh2._LIBSSH2_POLLFD fds = scope.allocateStruct(libssh2._LIBSSH2_POLLFD.class);
                fds.type$set((byte) libssh2_h.LIBSSH2_POLLFD_CHANNEL);
                fds.fd$get().channel$set(ptrChannel);
                fds.events$set(libssh2_h.LIBSSH2_POLLFD_POLLIN | libssh2_h.LIBSSH2_POLLFD_POLLOUT);

                while (!quit) {
                    rc = libssh2_h.libssh2_poll(fds.ptr(), 1, 10);
                    if (rc < 1) {
                        continue;
                    }

                    active = 0;

                    System.out.println("FLAGS: " + fds.revents$get());

                    // can read
                    if ((fds.revents$get() & libssh2_h.LIBSSH2_POLLFD_POLLIN) == libssh2_h.LIBSSH2_POLLFD_POLLIN) {
                        active++;

                        Pointer<Byte> buffer = scope.allocate(NativeTypes.INT8, BUFSIZE);
                        read = libssh2_h.libssh2_channel_read_ex(ptrChannel, 0, buffer, BUFSIZE);
                        if (read != libssh2_h.LIBSSH2_ERROR_EAGAIN && read < 0) {
                            throw new RuntimeException("Error reading from ssh channel!");
                        }

                        System.out.println(Pointer.toString(buffer));
                    }

                    // can write
                    if ((fds.revents$get() & libssh2_h.LIBSSH2_POLLFD_POLLOUT) == libssh2_h.LIBSSH2_POLLFD_POLLOUT && active == 0) {
                        active++;

                        Console console = System.console();
                        String cmd = console.readLine("Enter cmd: ");
                        if (cmd.equals("quit") || cmd.equals("logout") || cmd.equals("exit")) {
                            quit = true;
                        } else {
                            final String requestTypeExec = "exec";
                            nio(() -> libssh2_h.libssh2_channel_process_startup(ptrChannel,
                                    scope.allocateCString(requestTypeExec), requestTypeExec.length(), scope.allocateCString(cmd), cmd.length()), "Error executing ssh command!");
//                            while (libssh2_h.LIBSSH2_ERROR_EAGAIN == (write = libssh2_h.libssh2_channel_write_ex(ptrChannel, 0, ptrCmd, cmd.length()))) {
//                                if (write != libssh2_h.LIBSSH2_ERROR_EAGAIN && write < 0) {
//                                    throw new RuntimeException("Error writing to ssh channel!");
//                                }
//                            }
                            nio(() -> libssh2_h.libssh2_channel_send_eof(ptrChannel), "Error writing eof to ssh channel!");
                        }
                    }

                    if ((fds.revents$get() & libssh2_h.LIBSSH2_POLLFD_CHANNEL_CLOSED) == libssh2_h.LIBSSH2_POLLFD_CHANNEL_CLOSED) {
                        if (active == 0) {
                            quit = true;
                        }
                    }
                }

//                while (!quit) {
//                    // READ
//                    while (0 == (rc = libssh2_h.libssh2_channel_eof(ptrChannel))) {
//                        if (rc < 0) {
//                            throw new RuntimeException("Failed reading remote EOF from ssh channel!");
//                        }
//
//                        Pointer<Byte> buffer = scope.allocate(NativeTypes.INT8, BUFSIZE);
////                        while (libssh2_h.LIBSSH2_ERROR_EAGAIN == (read = libssh2_h.libssh2_channel_read_ex(ptrChannel, 0, buffer, BUFSIZE))) {
//                        read = libssh2_h.libssh2_channel_read_ex(ptrChannel, 0, buffer, BUFSIZE);
//                        if (read != libssh2_h.LIBSSH2_ERROR_EAGAIN && read < 0) {
//                            throw new RuntimeException("Error reading from ssh channel!");
//                        }
////                        }
//                        System.out.println(Pointer.toString(buffer));
//                    }
//
//                    // WRITE
//                    Console console = System.console();
//                    String cmd = console.readLine("Enter cmd: ");
//                    if (cmd.equals("quit") || cmd.equals("logout") || cmd.equals("exit")) {
//                        quit = true;
//                    } else {
//                        final Pointer<Byte> ptrCmd = scope.allocateCString(cmd);
//                        while (libssh2_h.LIBSSH2_ERROR_EAGAIN == (write = libssh2_h.libssh2_channel_write_ex(ptrChannel, 0, ptrCmd, cmd.length()))) {
//                            if (write != libssh2_h.LIBSSH2_ERROR_EAGAIN && write < 0) {
//                                throw new RuntimeException("Error writing to ssh channel!");
//                            }
//                        }
//                        libssh2_h.libssh2_channel_send_eof(ptrChannel);
//                    }
//                }

                System.out.println("Good bye!");
            } finally {
                // clean up
                if (!ptrChannel.isNull()) {
                    libssh2_h.libssh2_channel_free(ptrChannel);
                }
                if (!ptrSession.isNull()) {
                    libssh2_h.libssh2_session_disconnect_ex(ptrSession, libssh2_h.SSH_DISCONNECT_BY_APPLICATION,
                            scope.allocateCString("Normal shutdown."), Pointer.ofNull());
                    libssh2_h.libssh2_session_free(ptrSession);
                }
            }
        } catch (Throwable t) {
            t.printStackTrace();
        } finally {
            libssh2_h.libssh2_exit();
        }
    }

    private static void parseArgs(String[] args) {
        if (args.length < 4) {
            throw new RuntimeException("Insufficient arguments!");
        }
        switch (args[0]) {
            case "-p":
                connType = 1;
                break;
            case "-k":
                connType = 2;
                break;
            default:
                throw new RuntimeException("Invalid authentication type!");
        }

        hostname = args[1];
        port = Integer.parseInt(args[2]);
        username = args[3];
    }

    // --- UTILS

    private static void nio(Supplier<Integer> supplier, String errorMsg) {
        int rc;
        while (libssh2_h.LIBSSH2_ERROR_EAGAIN == (rc = supplier.get())) {
            if (rc != libssh2_h.LIBSSH2_ERROR_EAGAIN && rc != 0) {
                throw new RuntimeException(errorMsg + " ERR: " + rc);
            }
        }
    }

    private static long connectFd(String address, int port) throws IOException {
        var socket = new Socket(address, port);
        var fs = (FileInputStream) socket.getInputStream();
        // a somewhat hacky way to get the socket's file id
        return fileNo(fs.getFD());
    }

    // @see - https://stackoverflow.com/a/48070332/10364676
    public static long fileNo(FileDescriptor fd) throws IOException {
        try {
            if (fd.valid()) {
                // windows builds use long handle
                long fileno = getFileDescriptorField(fd, "handle", false);
                if (fileno != -1) {
                    return fileno;
                }
                // unix builds use int fd
                return getFileDescriptorField(fd, "fd", true);
            }
        } catch (IllegalAccessException e) {
            throw new IOException("unable to access handle/fd fields in FileDescriptor", e);
        } catch (NoSuchFieldException e) {
            throw new IOException("FileDescriptor in this JVM lacks handle/fd fields", e);
        }
        return -1;
    }

    private static long getFileDescriptorField(FileDescriptor fd, String fieldName, boolean isInt) throws NoSuchFieldException, IllegalAccessException {
        Field field = FileDescriptor.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        long value = isInt ? field.getInt(fd) : field.getLong(fd);
        field.setAccessible(false);
        return value;
    }

    private final static char[] hexArray = "0123456789abcdef".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 3];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xff;
            hexChars[j * 3] = hexArray[v >>> 4];
            hexChars[j * 3 + 1] = hexArray[v & 0x0f];
            hexChars[j * 3 + 2] = ':';
        }
        return new String(hexChars).substring(0, hexChars.length - 1);
    }
}
