package com.enterprise.employee.mapper;

import com.enterprise.employee.dto.EmployeeDTO;
import com.enterprise.employee.entity.Employee;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link EmployeeMapper}.
 */
class EmployeeMapperTest {

    private EmployeeMapper mapper;
    private Employee entity;
    private EmployeeDTO dto;

    @BeforeEach
    void setUp() {
        mapper = new EmployeeMapper();
        entity = Employee.builder()
                .id(7L)
                .employeeId("EMP-7")
                .firstName("Ada")
                .lastName("Lovelace")
                .email("ada@enterprise.com")
                .department("R&D")
                .designation("Pioneer")
                .salary(new BigDecimal("123456.78"))
                .joiningDate(LocalDate.of(2020, 12, 10))
                .build();

        dto = EmployeeDTO.builder()
                .id(7L)
                .employeeId("EMP-7")
                .firstName("Ada")
                .lastName("Lovelace")
                .email("ada@enterprise.com")
                .department("R&D")
                .designation("Pioneer")
                .salary(new BigDecimal("123456.78"))
                .joiningDate(LocalDate.of(2020, 12, 10))
                .build();
    }

    @Test
    @DisplayName("toDTO - converts entity to DTO")
    void toDTO_success() {
        EmployeeDTO result = mapper.toDTO(entity);
        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(7L);
        assertThat(result.getEmployeeId()).isEqualTo("EMP-7");
        assertThat(result.getFirstName()).isEqualTo("Ada");
        assertThat(result.getEmail()).isEqualTo("ada@enterprise.com");
        assertThat(result.getSalary()).isEqualByComparingTo("123456.78");
    }

    @Test
    @DisplayName("toDTO - null entity returns null")
    void toDTO_null() {
        assertThat(mapper.toDTO(null)).isNull();
    }

    @Test
    @DisplayName("toEntity - converts DTO to entity")
    void toEntity_success() {
        Employee result = mapper.toEntity(dto);
        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(7L);
        assertThat(result.getFirstName()).isEqualTo("Ada");
        assertThat(result.getJoiningDate()).isEqualTo(LocalDate.of(2020, 12, 10));
    }

    @Test
    @DisplayName("toEntity - null DTO returns null")
    void toEntity_null() {
        assertThat(mapper.toEntity(null)).isNull();
    }

    @Test
    @DisplayName("toDTOList - converts list of entities")
    void toDTOList_success() {
        List<EmployeeDTO> result = mapper.toDTOList(List.of(entity));
        assertThat(result).hasSize(1);
        assertThat(result.get(0).getEmployeeId()).isEqualTo("EMP-7");
    }

    @Test
    @DisplayName("toDTOList - null returns empty list")
    void toDTOList_null() {
        assertThat(mapper.toDTOList(null)).isEmpty();
    }
}
