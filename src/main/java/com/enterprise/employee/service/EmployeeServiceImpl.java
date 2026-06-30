package com.enterprise.employee.service;

import com.enterprise.employee.dto.EmployeeDTO;
import com.enterprise.employee.entity.Employee;
import com.enterprise.employee.exception.EmployeeNotFoundException;
import com.enterprise.employee.mapper.EmployeeMapper;
import com.enterprise.employee.repository.EmployeeRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Default implementation of {@link EmployeeService}.
 * Uses constructor injection for required collaborators.
 */
@Service
@Transactional
public class EmployeeServiceImpl implements EmployeeService {

    private static final Logger log = LoggerFactory.getLogger(EmployeeServiceImpl.class);

    private final EmployeeRepository employeeRepository;
    private final EmployeeMapper employeeMapper;

    public EmployeeServiceImpl(EmployeeRepository employeeRepository, EmployeeMapper employeeMapper) {
        this.employeeRepository = employeeRepository;
        this.employeeMapper = employeeMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public List<EmployeeDTO> getAllEmployees() {
        log.debug("Fetching all employees");
        List<Employee> employees = employeeRepository.findAll();
        if (employees == null) {
            log.warn("Repository returned null employee list; returning empty list");
            return List.of();
        }
        log.info("Retrieved {} employees", employees.size());
        return employeeMapper.toDTOList(employees);
    }

    @Override
    @Transactional(readOnly = true)
    public EmployeeDTO getEmployeeById(Long id) {
        log.debug("Fetching employee by id={}", id);
        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new EmployeeNotFoundException("Employee not found with id: " + id));
        return employeeMapper.toDTO(employee);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<EmployeeDTO> getEmployeeByEmployeeId(String employeeId) {
        log.debug("Fetching employee by employeeId={}", employeeId);
        return employeeRepository.findByEmployeeId(employeeId).map(employeeMapper::toDTO);
    }

    @Override
    public EmployeeDTO createEmployee(EmployeeDTO employeeDTO) {
        log.debug("Creating employee with employeeId={}", employeeDTO.getEmployeeId());
        if (employeeRepository.existsByEmployeeId(employeeDTO.getEmployeeId())) {
            throw new IllegalArgumentException(
                    "Employee with employeeId already exists: " + employeeDTO.getEmployeeId());
        }
        Employee entity = employeeMapper.toEntity(employeeDTO);
        entity.setId(null);
        Employee saved = employeeRepository.save(entity);
        log.info("Created employee id={}, employeeId={}", saved.getId(), saved.getEmployeeId());
        return employeeMapper.toDTO(saved);
    }

    @Override
    public EmployeeDTO updateEmployee(Long id, EmployeeDTO employeeDTO) {
        log.debug("Updating employee id={}", id);
        Employee existing = employeeRepository.findById(id)
                .orElseThrow(() -> new EmployeeNotFoundException("Employee not found with id: " + id));
        existing.setFirstName(employeeDTO.getFirstName());
        existing.setLastName(employeeDTO.getLastName());
        existing.setEmail(employeeDTO.getEmail());
        existing.setDepartment(employeeDTO.getDepartment());
        existing.setDesignation(employeeDTO.getDesignation());
        existing.setSalary(employeeDTO.getSalary());
        existing.setJoiningDate(employeeDTO.getJoiningDate());
        Employee updated = employeeRepository.save(existing);
        log.info("Updated employee id={}", updated.getId());
        return employeeMapper.toDTO(updated);
    }

    @Override
    public void deleteEmployee(Long id) {
        log.debug("Deleting employee id={}", id);
        if (!employeeRepository.existsById(id)) {
            throw new EmployeeNotFoundException("Employee not found with id: " + id);
        }
        employeeRepository.deleteById(id);
        log.info("Deleted employee id={}", id);
    }
}
