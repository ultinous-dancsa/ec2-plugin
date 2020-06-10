package hudson.plugins.ec2.util;

import com.trilead.ssh2.Session;

import java.io.InputStream;
import java.io.OutputStream;

public class RemoteSshLongProcess implements RemoteLongProcess {
    private Session session;

    public RemoteSshLongProcess(Session session) {
        this.session = session;
    }

    @Override
    public InputStream getStdout() {
        return session.getStdout();
    }

    @Override
    public OutputStream getStdin() {
        return session.getStdin();
    }

    @Override
    public void destroy() {
        session.close();
    }
}
