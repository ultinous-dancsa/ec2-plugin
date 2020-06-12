package hudson.plugins.ec2.util;

import hudson.model.TaskListener;
import hudson.plugins.ec2.EC2Cloud;
import hudson.plugins.ec2.EC2Computer;

import java.util.logging.Level;
import java.util.logging.Logger;

public class LogHelper {
    private final Logger LOGGER;

    public LogHelper(String classname){
        LOGGER = Logger.getLogger(classname);
    }

    public void log(Level level, EC2Computer computer, TaskListener listener, String message) {
        EC2Cloud.log(LOGGER, level, listener, message);
    }

    public void logException(EC2Computer computer, TaskListener listener, String message, Throwable exception) {
        EC2Cloud.log(LOGGER, Level.WARNING, listener, message, exception);
    }

    public void logInfo(EC2Computer computer, TaskListener listener, String message) {
        log(Level.INFO, computer, listener, message);
    }

    public void logWarning(EC2Computer computer, TaskListener listener, String message) {
        log(Level.WARNING, computer, listener, message);
    }

}
