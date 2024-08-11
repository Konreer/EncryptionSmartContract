package DTO;

import entry.UserEntry;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class DataDTO implements Serializable {
    private final String username;
    private final List<PasswordDTO> data;

    public DataDTO(String username) {
        this.username = username;
        this.data = new ArrayList<>();
    }

    public DataDTO(UserEntry userEntry) {
        this.username = userEntry.getUsername();
        this.data = new ArrayList<>();
    }

    public String getUsername() {
        return username;
    }

    public List<PasswordDTO> getData() {
        return data;
    }

    public void addPassword(PasswordDTO passwordDTO) {
        this.data.add(passwordDTO);
    }
}
