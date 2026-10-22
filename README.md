🛡️ CyberShield
CyberShield is a full-stack cybersecurity monitoring dashboard designed to help users review security activity, inspect suspicious events, and manage security-related records through a web interface.

The project includes a React frontend and an Express.js backend connected to MongoDB. Authentication uses JSON Web Tokens (JWT), passwords are hashed with bcrypt, and administrative routes use role-based authorization.
✨ Features
- User authentication — register, sign in, and retrieve the current authenticated user.
- Security dashboard — view security-event statistics and recent activity.
- Security event monitoring — review recorded events, including successful and failed sign-ins.
- Suspicious activity alerts — surface suspicious activity for investigation.
- Event severity and status tracking — classify events by severity and review status.
- Admin endpoints — access additional security information and update event status with administrator permissions.
- Protected API routes — validate JWTs and restrict administrator-only operations.
- Input validation — validate authentication input before processing requests.
🧰 Tech Stack
Area	Technology
Frontend	React, Vite, JavaScript, CSS
Routing	React Router
Backend	Node.js, Express.js
Database	MongoDB, Mongoose
Authentication	JSON Web Tokens (JWT), bcryptjs
Validation	Zod
Middleware / utilities	CORS, dotenv, Helmet, Morgan, express-rate-limit


📁 Project Structure
cyber/
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── assets/
│   │   ├── api.js
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
└── backend/
    ├── src/
    │   ├── config/
    │   ├── controllers/
    │   ├── middleware/
    │   ├── models/
    │   ├── routes/
    │   └── services/
    ├── server.js
    └── package.json
⚙️ Run Locally
Prerequisites
- Node.js and npm
- A MongoDB database (local MongoDB or MongoDB Atlas)
- Git (optional, for cloning the repository)
1. Clone the repository
git clone YOUR_GITHUB_REPOSITORY_URL
cd cyber
Replace YOUR_GITHUB_REPOSITORY_URL with your repository URL. If your downloaded project has an extra parent folder, open the folder that contains frontend and backend.
2. Configure the backend
cd backend
npm install
Create a file named .env inside the backend folder:
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=replace_with_a_long_random_secret
JWT_EXPIRES_IN=1d
Replace the example values with your own configuration. Keep your database connection string and JWT secret private. Do not commit .env to GitHub.

Start the backend:
node server.js
The backend uses http://localhost:5000 by default. When the database connection succeeds, the server logs a MongoDB connection confirmation.
3. Configure and start the frontend
Open a second terminal from the project root:
cd frontend
npm install
npm run dev
Vite will print the local frontend URL in the terminal, usually http://localhost:5173.

The frontend API helper is frontend/src/api.js. For local development, its API base URL should point to:
const API_BASE_URL = "http://localhost:5000/api";
Keep the backend running while using the frontend. Never put MongoDB credentials or the JWT signing secret in frontend code.
🔌 API Overview
The backend exposes these main route groups:
Method	Endpoint	Purpose
POST	/api/auth/register	Register a user
POST	/api/auth/login	Sign in and receive an authentication token
GET	/api/auth/me	Retrieve the authenticated user's details
GET	/api/security/dashboard	Retrieve dashboard statistics and recent activity
GET	/api/security/events	Retrieve security events
GET	/api/security/alerts	Retrieve suspicious-activity alerts
GET	/api/admin/dashboard	Retrieve administrator dashboard data (admin access required)


Additional administrator endpoints are defined in backend/src/routes/adminRoutes.js. Protected endpoints require a valid JWT in the Authorization: Bearer <token> header; administrator endpoints also require the appropriate role.
🔐 Security Notes
- Keep .env files, database passwords, JWT secrets, and access tokens out of source control.
- If a secret is accidentally pushed to GitHub, rotate it; deleting it from the latest commit alone may not remove it from repository history.
- Use a strong, unique JWT_SECRET in your own environment.
- Configure database network access and permissions carefully.
- Before production use, restrict CORS to trusted frontend origins and review deployment-specific security settings.
🛠️ Troubleshooting
- MongoDB connection fails: verify MONGO_URI, the database user's credentials, and MongoDB network access.
- Frontend cannot reach the backend: confirm the backend is running on port 5000 and frontend/src/api.js points to the correct API URL.
- Unauthorized / forbidden response: sign in again and check whether the account has the required role for administrator-only endpoints.
- Missing environment variable: check that backend/.env exists and that the variable names match those used by the backend code.
🚧 Project Status
CyberShield is an ongoing project. Features and implementation details may change as development continues.
👨‍💻 Author
Shaik Arshad Ahmad
If you find this project useful, consider giving the repository a ⭐ on GitHub<img width="1902" height="887" alt="Screenshot 2026-10-22 231320" src="https://github.com/user-attachments/assets/09755cd3-7446-4271-a122-e75e237d6f2d" />
<img width="1917" height="907" alt="Screenshot 2026-10-22 231219" src="https://github.com/user-attachments/assets/ea92fdef-3974-4218-bcc5-e696093e9918" />
<img width="1916" height="888" alt="Screenshot 2026-10-22 231041" src="https://github.com/user-attachments/assets/b14c6064-482c-4e9f-9df3-4db7d5638fb0" />
<img width="1915" height="897" alt="Screenshot 2026-10-22 231021" src="https://github.com/user-attachments/assets/db183958-31f5-4203-b314-015216ac6d85" />
<img width="1917" height="897" alt="Screenshot 2026-10-22 230920" src="https://github.com/user-attachments/assets/3bc99cd9-710b-46cf-abee-55f57f996270" />
<img width="1865" height="902" alt="Screenshot 2026-10-22 230833" src="https://github.com/user-attachments/assets/bd07b61e-70f4-4b52-9f02-02420825b641" />
