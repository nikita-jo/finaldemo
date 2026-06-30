package com.enterprise.employee.service;

import com.enterprise.employee.dto.EmployeeDTO;
import com.enterprise.employee.entity.Employee;
import com.enterprise.employee.exception.EmployeeNotFoundException;
import com.enterprise.employee.mapper.EmployeeMapper;
import com.enterprise.employee.repository.EmployeeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link EmployeeServiceImpl} using JUnit 5 and Mockito.
 */
@ExtendWith(MockitoExtension.class)
class EmployeeServiceImplTest {

    @Mock
    private EmployeeRepository employeeRepository;

    @Mock
    private EmployeeMapper employeeMapper;

    @InjectMocks
    private EmployeeServiceImpl employeeService;

    private Employee sampleEmployee;
    private EmployeeDTO sampleDTO;

    @BeforeEach
    void setUp() {
        sampleEmployee = Employee.builder()
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

        sampleDTO = EmployeeDTO.builder()
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

    // ------------------------------------------------------------------
    // getAllEmployees
    // ------------------------------------------------------------------

    @Test
    @DisplayName("getAllEmployees - success: returns mapped DTOs")
    void getAllEmployees_success() {
        when(employeeRepository.findAll()).thenReturn(List.of(sampleEmployee));
        when(employeeMapper.toDTOList(List.of(sampleEmployee))).thenReturn(List.of(sampleDTO));

        List<EmployeeDTO> result = employeeService.getAllEmployees();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getEmployeeId()).isEqualTo("EMP-001");
        verify(employeeRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("getAllEmployees - empty list returns empty result")
    void getAllEmployees_empty() {
        when(employeeRepository.findAll()).thenReturn(Collections.emptyList());
        when(employeeMapper.toDTOList(Collections.emptyList())).thenReturn(Collections.emptyList());

        List<EmployeeDTO> result = employeeService.getAllEmployees();

        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("getAllEmployees - null from repository returns empty list")
    void getAllEmployees_nullFromRepository() {
        when(employeeRepository.findAll()).thenReturn(null);
        when(employeeMapper.toDTOList(null)).thenReturn(Collections.emptyList());

        List<EmployeeDTO> result = employeeService.getAllEmployees();

        assertThat(result).isEmpty();
    }

    // ------------------------------------------------------------------
    // getEmployeeById
    // ------------------------------------------------------------------

    @Test
    @DisplayName("getEmployeeById - success")
    void getEmployeeById_success() {
        when(employeeRepository.findById(1L)).thenReturn(Optional.of(sampleEmployee));
        when(employeeMapper.toDTO(sampleEmployee)).thenReturn(sampleDTO);

        EmployeeDTO result = employeeService.getEmployeeById(1L);

        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(1L);
    }

    @Test
    @DisplayName("getEmployeeById - not found throws EmployeeNotFoundException")
    void getEmployeeById_notFound() {
        when(employeeRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> employeeService.getEmployeeById(99L))
                .isInstanceOf(EmployeeNotFoundException.class)
                .hasMessageContaining("99");
    }

    // ------------------------------------------------------------------
    // getEmployeeByEmployeeId
    // ------------------------------------------------------------------

    @Test
    @DisplayName("getEmployeeByEmployeeId - found")
    void getEmployeeByEmployeeId_found() {
        when(employeeRepository.findByEmployeeId("EMP-001")).thenReturn(Optional.of(sampleEmployee));
        when(employeeMapper.toDTO(sampleEmployee)).thenReturn(sampleDTO);

        Optional<EmployeeDTO> result = employeeService.getEmployeeByEmployeeId("EMP-001");

        assertThat(result).isPresent();
        assertThat(result.get().getEmployeeId()).isEqualTo("EMP-001");
    }

    @Test
    @DisplayName("getEmployeeByEmployeeId - not found")
    void getEmployeeByEmployeeId_notFound() {
        when(employeeRepository.findByEmployeeId("NOPE")).thenReturn(Optional.empty());

        Optional<EmployeeDTO> result = employeeService.getEmployeeByEmployeeId("NOPE");

        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("getEmployeeByEmployeeId - null id returns empty")
    void getEmployeeByEmployeeId_nullId() {
        when(employeeRepository.findByEmployeeId(null)).thenReturn(Optional.empty());

        Optional<EmployeeDTO> result = employeeService.getEmployeeByEmployeeId(null);

        assertThat(result).isEmpty();
    }

    // ------------------------------------------------------------------
    // createEmployee
    // ------------------------------------------------------------------

    @Test
    @DisplayName("createEmployee - success")
    void createEmployee_success() {
        when(employeeRepository.existsByEmployeeId("EMP-001")).thenReturn(false);
        when(employeeMapper.toEntity(sampleDTO)).thenReturn(sampleEmployee);
        when(employeeRepository.save(any(Employee.class))).thenReturn(sampleEmployee);
        when(employeeMapper.toDTO(sampleEmployee)).thenReturn(sampleDTO);

        EmployeeDTO result = employeeService.createEmployee(sampleDTO);

        assertThat(result).isNotNull();
        ArgumentCaptor<Employee> captor = ArgumentCaptor.forClass(Employee.class);
        verify(employeeRepository).save(captor.capture());
        assertThat(captor.getValue().getId()).isNull();
    }

    @Test
    @DisplayName("createEmployee - duplicate employeeId throws IllegalArgumentException")
    void createEmployee_duplicate() {
        when(employeeRepository.existsByEmployeeId("EMP-001")).thenReturn(true);

        assertThatThrownBy(() -> employeeService.createEmployee(sampleDTO))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("EMP-001");

        verify(employeeRepository, never()).save(any());
    }

    // ------------------------------------------------------------------
    // updateEmployee
    // ------------------------------------------------------------------

    @Test
    @DisplayName("updateEmployee - success")
    void updateEmployee_success() {
        EmployeeDTO update = EmployeeDTO.builder()
                .firstName("Updated")
                .lastName("Name")
                .email("updated@enterprise.com")
                .department("Ops")
                .designation("Lead")
                .salary(new BigDecimal("200000.00"))
                .joiningDate(LocalDate.of(2025, 1, 1))
                .build();

        when(employeeRepository.findById(1L)).thenReturn(Optional.of(sampleEmployee));
        when(employeeRepository.save(any(Employee.class))).thenReturn(sampleEmployee);
        when(employeeMapper.toDTO(sampleEmployee)).thenReturn(sampleDTO);

        EmployeeDTO result = employeeService.updateEmployee(1L, update);

        assertThat(result).isNotNull();
        verify(employeeRepository, times(1)).save(any(Employee.class));
    }

    @Test
    @DisplayName("updateEmployee - not found throws EmployeeNotFoundException")
    void updateEmployee_notFound() {
        when(employeeRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> employeeService.updateEmployee(99L, sampleDTO))
                .isInstanceOf(EmployeeNotFoundException.class);

        verify(employeeRepository, never()).save(any());
    }

    // ------------------------------------------------------------------
    // deleteEmployee
    // ------------------------------------------------------------------

    @Test
    @DisplayName("deleteEmployee - success")
    void deleteEmployee_success() {
        when(employeeRepository.existsById(1L)).thenReturn(true);

        employeeService.deleteEmployee(1L);

        verify(employeeRepository, times(1)).deleteById(1L);
    }

    @Test
    @DisplayName("deleteEmployee - not found throws EmployeeNotFoundException")
    void deleteEmployee_notFound() {
        when(employeeRepository.existsById(99L)).thenReturn(false);

        assertThatThrownBy(() -> employeeService.deleteEmployee(99L))
                .isInstanceOf(EmployeeNotFoundException.class);

        verify(employeeRepository, never()).deleteById(anyLong());
    }

    @Test
    @DisplayName("getAllEmployees - handles multiple employees")
    void getAllEmployees_multiple() {
        Employee second = Employee.builder()
                .id(2L).employeeId("EMP-002").firstName("Jane").lastName("Doe")
                .email("jane@enterprise.com").department("HR").designation("Manager")
                .salary(new BigDecimal("120000.00")).joiningDate(LocalDate.of(2023, 5, 10))
                .build();
        EmployeeDTO secondDTO = EmployeeDTO.builder()
                .id(2L).employeeId("EMP-002").firstName("Jane").lastName("Doe")
                .email("jane@enterprise.com").department("HR").designation("Manager")
                .salary(new BigDecimal("120000.00")).joiningDate(LocalDate.of(2023, 5, 10))
                .build();

        when(employeeRepository.findAll()).thenReturn(List.of(sampleEmployee, second));
        when(employeeMapper.toDTOList(List.of(sampleEmployee, second)))
                .thenReturn(List.of(sampleDTO, secondDTO));

        List<EmployeeDTO> result = employeeService.getAllEmployees();

        assertThat(result).hasSize(2);
    }

    @Test
    @DisplayName("getEmployeeById - uses argument captor for save")
    void createEmployee_usesArgumentCaptor() {
        when(employeeRepository.existsByEmployeeId(eq("EMP-001"))).thenReturn(false);
        when(employeeMapper.toEntity(sampleDTO)).thenReturn(sampleEmployee);
        when(employeeRepository.save(any(Employee.class))).thenReturn(sampleEmployee);
        when(employeeMapper.toDTO(sampleEmployee)).thenReturn(sampleDTO);

        employeeService.createEmployee(sampleDTO);

        verify(employeeMapper, times(1)).toEntity(sampleDTO);
        verify(employeeMapper, times(1)).toDTO(sampleEmployee);
    }

    @Test
    @DisplayName("createEmployee - null DTO throws NullPointerException at mapper")
    void createEmployee_nullDTO() {
        when(employeeRepository.existsByEmployeeId(anyString())).thenReturn(false);
        when(employeeMapper.toEntity(null)).thenReturn(null);

        // toEntity returns null then save(null) would throw — we assert it throws
        assertThatThrownBy(() -> employeeService.createEmployee(null))
                .isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
    }
}
