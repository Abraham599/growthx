# GrowthX Backend Assignment (Assignment Portal)

This project is an Express-based API that manages admin registration, login, and assignment-related operations. The API allows admins to register, log in, view, accept, and reject user assignments. Users can upload assignments once they log in.

## Features
- **Admin Registration & Login**: Secure registration and login for admins using bcrypt for password hashing and JWT for authentication.
- **User Assignment Upload**: Authenticated users can upload assignments and assign them to specific admins.
- **Admin Assignment Management**: Admins can view, accept, or reject user assignments.

---

## Prerequisites

- Node.js and npm installed
- MongoDB Cluster for database connection

---

## Steps to Run the Codebase

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Set up MongoDB**: 
   - Create a MongoDB cluster.
   - Obtain the connection string for your database.
   - Open `server.ts` and paste the MongoDB connection string inside `mongoose.connect('')`.

3. **Configure JWT Secret**: 
   - In `config.ts`, set the `JWT_SECRET` to any secret string of your choice.

4. **Run the Backend**:
   ```bash
   npm run dev
   ```
   - The backend will run on **PORT 3000** by default.

---

## API Endpoints and Request Body Formats

### 1. **Admin and User Registration**
   - **URL**: `/api/users/register` or `/api/admin/register`
   - **Method**: POST
   - **Request Body**:
   ```json
   {
      "username": "qwerty",
      "password": "1234567",
      "confirmPassword": "1234567"
   }
   ```

### 2. **Admin and User Login**
   - **URL**: `/api/users/login` or `/api/admin/login`
   - **Method**: POST
   - **Request Body**:
   ```json
   {
      "username": "richy",
      "password": "1234567"
   }
   ```
   - **Authentication**: After login, you'll receive a JWT token in the response. Use this token to authenticate future requests:
     - In Postman/Hoppscotch, create a header with the key `Authorization` and value `Bearer <token>`.

### 3. **User Assignment Upload**
   - **URL**: `/api/users/upload`
   - **Method**: POST
   - **Request Body**:
   ```json
   {
      "task": "assignment successfully uploaded",
      "admin": "abcde"
   }
   ```
   - **Note**: The `userId` is fetched using the JWT Bearer token provided in the headers.

### 4. **Get All Admins**
   - **URL**: `/api/users/admins`
   - **Method**: GET

### 5. **Get Assignments for Admins**
   - **URL**: `/api/admin/assignments`
   - **Method**: GET
   - **Authentication**: Admin must be authenticated via JWT.

### 6. **Accept Assignment**
   - **URL**: `/api/admin/assignments/:id/accept`
   - **Method**: POST
   - **Authentication**: Admin must be authenticated via JWT.

### 7. **Reject Assignment**
   - **URL**: `/api/admin/assignments/:id/reject`
   - **Method**: POST
   - **Authentication**: Admin must be authenticated via JWT.

---

## Usage Guide

1. **Register a new admin or user** using the appropriate endpoint.
2. **Log in** with the credentials to receive a JWT token.
3. **Set the JWT token** in your headers as `Bearer <token>` for protected routes.
4. **Upload assignments** as a user, or manage them as an admin (view, accept, reject).

---

## Important Notes

- **JWT Bearer Token**: After successful login, always include the token in the `Authorization` header when accessing protected routes. Remember the format should look like this `Bearer <token>`.
- **Assignment Operations**: Only admins can accept or reject assignments, and these actions require authentication via JWT.
