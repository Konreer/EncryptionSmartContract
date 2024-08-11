package entry;

import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.HashSet;
import java.util.Set;

@DataType()
public final class UserEntry {
    @Property()
    private final String username;
    @Property()
    private Set<PasswordEntry> passwordEntrySet;

    public UserEntry(String username, Set<PasswordEntry> passwordEntrySet) {
        this.username = username;
        this.passwordEntrySet = passwordEntrySet;
    }

    public UserEntry(String username) {
        this.username = username;
        this.passwordEntrySet = new HashSet<>();
    }

    public Set<PasswordEntry> getPasswordEntrySet() {
        return passwordEntrySet;
    }

    public void addPasswordEntry(PasswordEntry passwordEntry) {
        this.passwordEntrySet.add(passwordEntry);
    }

    public void setPasswordEntrySet(HashSet<PasswordEntry> passwordEntrySet) {
        this.passwordEntrySet = passwordEntrySet;
    }

    public String getUsername() {
        return username;
    }


}