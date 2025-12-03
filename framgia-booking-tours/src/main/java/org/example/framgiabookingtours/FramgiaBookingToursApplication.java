package org.example.framgiabookingtours;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class FramgiaBookingToursApplication {

    public static void main(String[] args) {
        SpringApplication.run(FramgiaBookingToursApplication.class, args);
    }

}
