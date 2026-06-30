package com.enterprise.employee.controller;

import com.enterprise.employee.dto.EmployeeDTO;
import com.enterprise.employee.exception.EmployeeNotFoundException;
import com.enterprise.employee.exception.GlobalExceptionHandler;
import com.enterprise.employee.service.EmployeeService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MockMvc tests for {@link EmployeeController}.
 * Exercises success paths, edge cases, and exception handling.
 */
@ExtendWith(MockitoExtension.class)
class EmployeeControllerTest {

    @Mock
    private EmployeeService employeeService;

    @InjectMocks
    private EmployeeController employeeController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private EmployeeDTO sample;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(employeeController)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());

        sample = EmployeeDTO.builder()
                .id(1L)
                .employeeId("EMP-001")
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
    @DisplayName("GET /api/v1/employees - returns 200 and list")
    void getAll_returnsList() throws Exception {
        when(employeeService.getAllEmployees()).thenReturn(List.of(sample));

        mockMvc.perform(get("/api/v1/employees"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].employeeId").value("EMP-001"))
                .andExpect(jsonPath("$[0].firstName").value("Sachin"))
                .andExpect(jsonPath("$[0].email").value("sachin.joshi@enterprise.com"));

        verify(employeeService, times(1)).getAllEmployees();
    }

    @Test
    @DisplayName("GET /api/v1/employees - empty list returns 200 with []")
    void getAll_empty() throws Exception {
        when(employeeService.getAllEmployees()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/v1/employees"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    @DisplayName("GET /api/v1/employees/{id} - returns single employee")
    void getById_success() throws Exception {
        when(employeeService.getEmployeeById(1L)).thenReturn(sample);

        mockMvc.perform(get("/api/v1/employees/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.employeeId").value("EMP-001"));
    }

    @Test
    @DisplayName("GET /api/v1/employees/{id} - 404 when not found")
    void getById_notFound() throws Exception {
        when(employeeService.getEmployeeById(99L))
                .thenThrow(new EmployeeNotFoundException("Employee not found with id: 99"));

        mockMvc.perform(get("/api/v1/employees/99"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.message").value("Employee not found with id: 99"));
    }

    @Test
    @DisplayName("POST /api/v1/employees - 201 created")
    void create_success() throws Exception {
        when(employeeService.createEmployee(any(EmployeeDTO.class))).thenReturn(sample);

        mockMvc.perform(post("/api/v1/employees")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(sample)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.employeeId").value("EMP-001"));
    }

    @Test
    @DisplayName("POST /api/v1/employees - 400 on validation failure")
    void create_validationFails() throws Exception {
        EmployeeDTO bad = EmployeeDTO.builder().build();

        mockMvc.perform(post("/api/v1/employees")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bad)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /api/v1/employees - 400 on invalid email")
    void create_invalidEmail() throws Exception {
        EmployeeDTO bad = EmployeeDTO.builder()
                .employeeId("EMP-X")
                .firstName("X").lastName("Y")
                .email("not-an-email")
                .department("D").designation("Z")
                .salary(new BigDecimal("1.00"))
                .joiningDate(LocalDate.now())
                .build();

        mockMvc.perform(post("/api/v1/employees")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bad)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("PUT /api/v1/employees/{id} - 200 on success")
    void update_success() throws Exception {
        when(employeeService.updateEmployee(eq(1L), any(EmployeeDTO.class))).thenReturn(sample);

        mockMvc.perform(put("/api/v1/employees/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(sample)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.employeeId").value("EMP-001"));
    }

    @Test
    @DisplayName("PUT /api/v1/employees/{id} - 404 when missing")
    void update_notFound() throws Exception {
        when(employeeService.updateEmployee(eq(99L), any(EmployeeDTO.class)))
                .thenThrow(new EmployeeNotFoundException("Employee not found with id: 99"));

        mockMvc.perform(put("/api/v1/employees/99")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(sample)))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("DELETE /api/v1/employees/{id} - 204 on success")
    void delete_success() throws Exception {
        mockMvc.perform(delete("/api/v1/employees/1"))
                .andExpect(status().isNoContent());

        verify(employeeService, times(1)).deleteEmployee(1L);
    }

    @Test
    @DisplayName("DELETE /api/v1/employees/{id} - 404 when missing")
    void delete_notFound() throws Exception {
        doThrow(new EmployeeNotFoundException("Employee not found with id: 99"))
                .when(employeeService).deleteEmployee(99L);

        mockMvc.perform(delete("/api/v1/employees/99"))
                .andExpect(status().isNotFound());
    }
}
