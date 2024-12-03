# File & Secret Sharing Web Application

## 📖 Overview
This is a web application designed for secure **file and secret sharing**, developed as part of a graduation project. Its purpose is to run **Chaos Experiments** to enhance it and its architecture resilience. The project covers the entire software lifecycle, from development and containerization to deployment on **Azure Kubernetes Service (AKS)** with **monitoring and chaos experiments**.

---

## 🚀 Features
- **User Account Management**: Registration, login, and profile updates.
- **Secret Management**: Create, share, and delete sensitive information (secrets) securely.
- **File Management**: Upload, share, download, and manage files.
- **Secure Encryption**: Uses AES encryption for secrets, with keys managed by Azure Key Vault.
- **Monitoring & Observability**: Integrated with Prometheus and Grafana.
- **Chaos Experiments**: Test system resilience under failure scenarios using Chaos Mesh.

---

## 🛠️ Technologies Used
### Frontend:
- **Vue.js**: Fast and flexible for user interface development.
  
### Backend:
- **Django**: For robust web application backend and API.

### Infrastructure:
- **Docker**: Containerization for consistent deployment.
- **Kubernetes**: Orchestration for scalability and resilience.
- **Azure Kubernetes Service (AKS)**: Cloud hosting for production.
- **Istio**: Service mesh for observability and traffic management.

---

## 📂 Technologies Used
 ```bash
   root
    ├── fssp_vuejs/         # Vue.js application
    ├── fssp_django/        # Django Restful API
    ├── fssp_k8s_manager/   # Backend-accessible API for querying Kubernetes resources
    ├── k8s_manifests/      # Kubernetes manifests
    └── README.md
    ```
  **fssp_vuejs** is the frontend application, built with Vue.js.
  **fssp_django** is the backend application, built with Django Restful API.
  **fssp_k8s_manager** is a backend-accessible API for querying Kubernetes resources made for the purpose of storing the files the users upload.
  **k8s_manifests** is the Kubernetes manifests for the deployment.
---

## 📝 License
This project is licensed under the MIT License.