package hudson.plugins.ec2.util;

import java.io.InputStream;
import java.io.OutputStream;

public interface RemoteLongProcess {
    InputStream getStdout();
    OutputStream getStdin();
    void destroy();
}
