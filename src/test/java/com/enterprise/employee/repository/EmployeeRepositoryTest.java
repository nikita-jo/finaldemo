package com.enterprise.employee.repository;

import com.enterprise.employee.entity.Employee;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JPA slice tests for {@link EmployeeRepository}.
 * Uses an in-memory H2 database via {@link DataJpaTest}.
 */
@DataJpaTest
class EmployeeRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private EmployeeRepository employeeRepository;

    private Employee emp;

    @BeforeEach
    void setUp() {
        emp = Employee.builder()
                .employeeId("EMP-100")
                .firstName("Alice")
                .lastName("Wonder")
                .email("alice@enterprise.com")
                .department("Engineering")
                .designation("Engineer")
                .salary(new BigDecimal("100000.00"))
                .joiningDate(LocalDate.of(2024, 6, 1))
                .build();
    }

    @Test
    @DisplayName("Save and retrieve an employee")
    void saveAndFind() {
        Employee saved = employeeRepository.save(emp);
        entityManager.flush();
        entityManager.clear();

        Optional<Employee> found = employeeRepository.findById(saved.getId());

        assertThat(found).isPresent();
        assertThat(found.get().getEmployeeId()).isEqualTo("EMP-100");
    }

    @Test
    @DisplayName("findByEmployeeId returns the right employee")
    void findByEmployeeId() {
        employeeRepository.saveAndFlush(emp);

        Optional<Employee> result = employeeRepository.findByEmployeeId("EMP-100");

        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("alice@enterprise.com");
    }

    @Test
    @DisplayName("findByEmployeeId returns empty for unknown id")
    void findByEmployeeId_unknown() {
        Optional<Employee> result = employeeRepository.findByEmployeeId("MISSING");

        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("findByEmail returns the right employee")
    void findByEmail() {
        employeeRepository.saveAndFlush(emp);

        Optional<Employee> result = employeeRepository.findByEmail("alice@enterprise.com");

        assertThat(result).isPresent();
    }

    @Test
    @DisplayName("findByEmail returns empty for unknown email")
    void findByEmail_unknown() {
        Optional<Employee> result = employeeRepository.findByEmail("nobody@enterprise.com");

        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("findByDepartment returns matching employees")
    void findByDepartment() {
        employeeRepository.saveAndFlush(emp);
        Employee other = Employee.builder()
                .employeeId("EMP-101")
                .firstName("Bob")
                .lastName("Builder")
                .email("bob@enterprise.com")
                .department("Engineering")
                .designation("Tech Lead")
                .salary(new BigDecimal("180000.00"))
                .joiningDate(LocalDate.of(2023, 1, 1))
                .build();
        employeeRepository.saveAndFlush(other);

        List<Employee> result = employeeRepository.findByDepartment("Engineering");

        assertThat(result).hasSize(2);
    }

    @Test
    @DisplayName("existsByEmployeeId returns true for existing id")
    void existsByEmployeeId_true() {
        employeeRepository.saveAndFlush(emp);

        assertThat(employeeRepository.existsByEmployeeId("EMP-100")).isTrue();
    }

    @Test
    @DisplayName("existsByEmployeeId returns false for missing id")
    void existsByEmployeeId_false() {
        assertThat(employeeRepository.existsByEmployeeId("NOPE")).isFalse();
    }

    @Test
    @DisplayName("findAll returns all persisted employees")
    void findAll_returnsAll() {
        employeeRepository.saveAndFlush(emp);
        Employee other = Employee.builder()
                .employeeId("EMP-200")
                .firstName("Carol")
                .lastName("Singh")
                .email("carol@enterprise.com")
                .department("Sales")
                .designation("Rep")
                .salary(new BigDecimal("80000.00"))
                .joiningDate(LocalDate.of(2025, 1, 1))
                .build();
        employeeRepository.saveAndFlush(other);

        List<Employee> all = employeeRepository.findAll();

        assertThat(all).hasSize(2);
    }

    @Test
    @DisplayName("deleteById removes the entity")
    void deleteById() {
        Employee saved = employeeRepository.saveAndFlush(emp);
        Long id = saved.getId();

        employeeRepository.deleteById(id);
        entityManager.flush();

        assertThat(employeeRepository.findById(id)).isEmpty();
    }

    @Test
    @DisplayName("count starts at zero and reflects inserts")
    void count() {
        assertThat(employeeRepository.count()).isZero();
        employeeRepository.saveAndFlush(emp);
        assertThat(employeeRepository.count()).isEqualTo(1L);
    }
}
