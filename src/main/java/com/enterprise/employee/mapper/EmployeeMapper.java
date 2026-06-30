package com.enterprise.employee.mapper;

import com.enterprise.employee.dto.EmployeeDTO;
import com.enterprise.employee.entity.Employee;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Mapper component for converting between Employee entity and EmployeeDTO.
 * Centralizes object conversion logic to keep controllers and services thin.
 */
@Component
public class EmployeeMapper {

    /**
     * Convert Employee entity to DTO.
     *
     * @param employee the entity
     * @return the DTO
     */
    public EmployeeDTO toDTO(Employee employee) {
        if (employee == null) {
            return null;
        }
        return EmployeeDTO.builder()
                .id(employee.getId())
                .employeeId(employee.getEmployeeId())
                .firstName(employee.getFirstName())
                .lastName(employee.getLastName())
                .email(employee.getEmail())
                .department(employee.getDepartment())
                .designation(employee.getDesignation())
                .salary(employee.getSalary())
                .joiningDate(employee.getJoiningDate())
                .build();
    }

    /**
     * Convert EmployeeDTO to Employee entity.
     *
     * @param dto the DTO
     * @return the entity
     */
    public Employee toEntity(EmployeeDTO dto) {
        if (dto == null) {
            return null;
        }
        return Employee.builder()
                .id(dto.getId())
                .employeeId(dto.getEmployeeId())
                .firstName(dto.getFirstName())
                .lastName(dto.getLastName())
                .email(dto.getEmail())
                .department(dto.getDepartment())
                .designation(dto.getDesignation())
                .salary(dto.getSalary())
                .joiningDate(dto.getJoiningDate())
                .build();
    }

    /**
     * Convert a list of Employee entities to a list of DTOs.
     *
     * @param employees the list of entities
     * @return the list of DTOs
     */
    public List<EmployeeDTO> toDTOList(List<Employee> employees) {
        if (employees == null) {
            return List.of();
        }
        return employees.stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
    }
}
