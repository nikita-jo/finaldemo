package com.enterprise.employee.controller;

import com.enterprise.employee.config.TestSecurityConfig;
import com.enterprise.employee.dto.EmployeeDTO;
import com.enterprise.employee.exception.GlobalExceptionHandler;
import com.enterprise.employee.service.EmployeeService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Slice test that boots the controller with Spring MVC infrastructure and the
 * GlobalExceptionHandler. Adds additional coverage over the standalone MockMvc
 * tests in {@link EmployeeControllerTest}.
 */
@WebMvcTest(controllers = EmployeeController.class)
@Import({GlobalExceptionHandler.class, TestSecurityConfig.class})
class EmployeeControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private EmployeeService employeeService;

    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    private EmployeeDTO sample() {
        return EmployeeDTO.builder()
                .id(1L)
                .employeeId("EMP-1")
                .firstName("Sachin")
                .lastName("Joshi")
                .email("sachin.joshi@enterprise.com")
                .department("Engineering")
                .designation("Senior Engineer")
                .salary(new BigDecimal("150000.00"))
                .joiningDate(LocalDate.of(2024, 1, 15))
                .build();
    }

    @Test
    @DisplayName("GET /api/v1/employees - WebMvc slice returns 200")
    void getAll_web() throws Exception {
        when(employeeService.getAllEmployees()).thenReturn(List.of(sample()));

        mockMvc.perform(get("/api/v1/employees"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].employeeId").value("EMP-1"));
    }

    @Test
    @DisplayName("POST /api/v1/employees - WebMvc slice returns 201 on success")
    void create_web() throws Exception {
        EmployeeDTO dto = sample();
        when(employeeService.createEmployee(any(EmployeeDTO.class))).thenReturn(dto);

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/v1/employees")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(dto)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.employeeId").value("EMP-1"));
    }
}
