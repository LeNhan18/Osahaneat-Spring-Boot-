package com.example.demo.Model;

import lombok.Builder;
import lombok.Data;
@Data
@Builder
public class Greeting {
    private long id;
    private String content;
}
