package hudson.plugins.ec2.ssh;

public class SshCredential {
    public String username;
    public String password;
    public char[] key;

    public SshCredential(String username, String password, char[] key) {
        if(password == null && key == null){
            throw new IllegalArgumentException();
        }else if(password != null && key != null){
            throw new IllegalArgumentException();
        }

        this.username = username;
        this.password = password;
        if (key != null) {
            this.key = key.clone();
        }
    }
}
