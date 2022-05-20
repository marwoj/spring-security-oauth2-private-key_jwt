package com.example.oauth2

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication(scanBasePackages = ["com.example.oauth2.config"])
class Oauth2Application

fun main(args: Array<String>) {
	runApplication<Oauth2Application>(*args)
}
