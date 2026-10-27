package com.example.signing;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class MainTest {

    @Test
    void mainRuns() {
        assertDoesNotThrow(() -> Main.main(new String[0]));
    }

    @Test
    void jsonLibraryIsAvailable() throws Exception {
        var json = new ObjectMapper().readTree("{\"credentialIDs\": [\"abc\"]}");
        assertEquals("abc", json.get("credentialIDs").get(0).asText());
    }
}
