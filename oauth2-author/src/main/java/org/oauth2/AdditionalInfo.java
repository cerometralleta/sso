package org.oauth2;

import lombok.Data;

import java.io.Serializable;

@Data
public class AdditionalInfo implements Serializable {

    private Long id;
    private Long groupId;
    private Long groupName;
    private String userName;
    private String name;
    private String avatar;
}
