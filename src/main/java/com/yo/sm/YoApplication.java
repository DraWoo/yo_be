package com.yo.sm;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class YoApplication {

	public static void main(String[] args) {
		//jasypt 암호화 키 설정
		System.setProperty("jasypt.encryptor.password", "zEey21sQzJ7haGPiV+Eor3ixey1yT/bYpwkvSyzw4Og=");

		//애플리케이션 실행
		SpringApplication.run(YoApplication.class, args);
	}

}
