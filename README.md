# Employee Management Service

Enterprise-grade Spring Boot 3.3.x REST API for managing employees, built with Java 21, JUnit 5, Mockito, JaCoCo, Docker, Trivy, CodeQL, SonarQube Community Edition, and NVIDIA NIM AI agents.

## Stack

- Java 21
- Spring Boot 3.3.3 (Web, Validation, Data JPA, Security, Actuator)
- H2 (in-memory) for dev / tests
- Lombok
- JUnit 5 + Mockito + AssertJ
- JaCoCo (HTML, XML, CSV)
- Maven
- SonarQube Community Edition (static analysis + Quality Gate)
- GitHub Actions, Docker, Trivy, CodeQL
- NVIDIA NIM API (Llama 3.1 70B Instruct)

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/v1/employees` | List all employees |
| GET | `/api/v1/employees/{id}` | Get one employee by id |
| POST | `/api/v1/employees` | Create a new employee |
| PUT | `/api/v1/employees/{id}` | Update an existing employee |
| DELETE | `/api/v1/employees/{id}` | Delete an employee |

## Run

```bash
mvn spring-boot:run
```

## Test + Coverage

```bash
mvn verify
```

Reports are written to `target/site/jacoco/`.

## Docker

```bash
docker build -t employee-management:1.0.0 .
docker run -p 8080:8080 employee-management:1.0.0
```

## Pipeline

See `.github/workflows/employee-pipeline.yml`. The pipeline runs:

1. Checkout
2. Setup Java 21
3. Cache Maven
4. Build
5. Unit Test
6. JaCoCo Coverage
7. SonarQube Analysis + Quality Gate
8. NVIDIA Test Coverage Agent
9. Trivy Scan
10. NVIDIA Security Review Agent
11. NVIDIA Auto Remediation Agent
12. CodeQL Analysis
13. Upload Reports
14. Deploy (only when all gates pass)

## NVIDIA Agents

The `scripts/` directory contains three agents that call the NVIDIA NIM API:

- `test-agent.py` -> `reports/coverage-summary.md`
- `security-agent.py` -> `reports/security-report.md`
- `security-fix-agent.py` -> `reports/security-fix-summary.md`, `patched-files.md`, `fix-log.md`

Set the `NVIDIA_API_KEY` environment variable (or `secrets.NVIDIA_API_KEY` in GitHub) to authenticate.
