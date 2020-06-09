package hudson.plugins.ec2.util;

import hudson.plugins.ec2.win.winrm.WindowsProcess;

import java.io.InputStream;
import java.io.OutputStream;

public class RemoteWinLongProcess implements RemoteLongProcess {
    private WindowsProcess process;


    public RemoteWinLongProcess(WindowsProcess process) {
        this.process = process;
    }

    @Override
    public InputStream getStdout() {
        return process.getStdout();
    }

    @Override
    public OutputStream getStdin() {
        return process.getStdin();
    }

    @Override
    public void destroy() {
        process.destroy();
    }
}
