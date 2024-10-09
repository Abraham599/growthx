import express from 'express';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { User } from '../models/userModel';
import { authenticateToken, isAdmin } from '../middleware/auth';
import { Assignment } from '../models/assignmentModel';
import { LoginSchema, RegisterSchema } from '../inputValidations';
import { JWT_SECRET } from '../config';
import bcrypt from 'bcryptjs';

// Create a new router instance for admin-specific routes
export const adminRouter = express.Router();

// Admin registration route
adminRouter.post('/register', async (req, res) => {
    try {
        // Validate the request body using the RegisterSchema
        const userData = RegisterSchema.safeParse(req.body);
        if (!userData.success) {
            // If validation fails, return an error response
            res.status(411).json({
                message: "Incorrect inputs"
            });
            return;
        }

        // Extract necessary data from the validated request body
        const { username, password, confirmPassword } = userData.data;

        // Check if the password and confirm password match
        if (password !== confirmPassword) {
            res.status(411).json({
                message: "Please confirm the desired password you have entered"
            });
            return;
        }

        // Check if an admin with the same username already exists
        const existingUser = await User.findOne({
            username: username,
            role: "admin"
        });

        // If the username is already taken, return an error response
        if (existingUser) {
            res.status(411).json({
                message: "Username already taken. Use a different username"
            });
            return;
        }

        // Create a new admin user with the provided username and password
        const user = await User.create({
            username: username,
            password: password,
            role: "admin"
        });

        // Generate a JWT token for the registered admin
        const userId = user._id;
        const token = jwt.sign({ userId }, JWT_SECRET);

        // Return a success response with the generated token
        res.status(201).json({ token, message: 'Admin registered successfully' });
    } catch (error) {
        // Handle errors during registration, including validation and unknown errors
        console.error('Registration error:', error);
        if (error instanceof z.ZodError) {
            res.status(400).json({ error: "Input validation error", details: error.errors });
        } else if (error instanceof Error) {
            res.status(400).json({ error: 'Registration failed, check your request body format', details: error.message });
        } else {
            res.status(400).json({ error: 'An unknown error occurred during registration' });
        }
    }
});

// Admin login route
adminRouter.post('/login', async (req, res) => {
    try {
        // Validate the request body using the LoginSchema
        const userData = LoginSchema.safeParse(req.body);
        if (!userData.success) {
            // If validation fails, return an error response
            res.status(411).json({
                message: "Incorrect inputs"
            });
            return;
        }

        // Extract username and password from the validated request body
        const { username, password } = userData.data;

        // Check if an admin with the provided username exists
        const existingUser = await User.findOne({
            username: username,
            role: "admin"
        });

        // If no admin is found, return an error response
        if (!existingUser) {
            res.status(411).json({
                message: "Admin doesn't exist"
            });
            return;
        }

        // Verify the provided password against the stored hash
        const isPasswordValid = await bcrypt.compare(password, existingUser.password);

        // If the password is incorrect, return an error response
        if (!isPasswordValid) {
            res.status(401).json({
                message: "Invalid password"
            });
            return;
        }

        // Generate a JWT token for the authenticated admin
        const token = jwt.sign({ userId: existingUser._id, role: existingUser.role }, JWT_SECRET);

        // Return a success response with the generated token
        res.json({ token, message: "Welcome to GrowthX assignment admin portal!" });
    } catch (error) {
        // Handle errors during login, including validation and unknown errors
        if (error instanceof z.ZodError) {
            res.status(400).json({ error: error.errors });
        } else {
            res.status(400).json({ error: 'Login failed' });
        }
    }
});

// Route to fetch assignments for the admin
adminRouter.get('/assignments', authenticateToken, isAdmin, async (req, res) => {
    try {
        // Ensure the authenticated user exists
        if (!req.user || !req.user.userId) {
            res.status(401).json({ error: 'User not authenticated properly' });
            return;
        }

        // Find the admin user by ID
        const user = await User.findById(req.user.userId);
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        // Fetch all assignments assigned to the current admin and return them
        const assignments = await Assignment.find({ admin: user.username })
            .select('userId task createdAt status');
        res.json(assignments);
    } catch (error) {
        // Handle errors during fetching assignments
        res.status(400).json({ error: 'Failed to fetch assignments' });
    }
});

// Route for admin to accept an assignment
adminRouter.post('/assignments/:id/accept', authenticateToken, isAdmin, async (req, res) => {
    try {
        // Ensure the authenticated user exists
        if (!req.user || !req.user.userId) {
            res.status(401).json({ error: 'User not authenticated properly' });
            return;
        }

        // Find the admin user by ID
        const user = await User.findById(req.user.userId);
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        // Update the assignment's status to 'accepted' if it belongs to the current admin
        const assignment = await Assignment.findOneAndUpdate(
            { _id: req.params.id, admin: user.username },
            { status: 'accepted' },
            { new: true }
        );

        // If the assignment is not found, return an error response
        if (!assignment) {
            res.status(404).json({ error: 'Assignment not found' });
            return;
        }

        // Return a success response with the updated assignment details
        res.json({ message: 'Assignment accepted successfully', details: assignment });
    } catch (error) {
        // Handle errors during accepting the assignment
        res.status(400).json({ error: 'Failed to accept assignment' });
    }
});

// Route for admin to reject an assignment
adminRouter.post('/assignments/:id/reject', authenticateToken, isAdmin, async (req, res) => {
    try {
        // Ensure the authenticated user exists
        if (!req.user || !req.user.userId) {
            res.status(401).json({ error: 'User not authenticated properly' });
            return;
        }

        // Find the admin user by ID
        const user = await User.findById(req.user.userId);
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        // Update the assignment's status to 'rejected' if it belongs to the current admin
        const assignment = await Assignment.findOneAndUpdate(
            { _id: req.params.id, admin: user.username },
            { status: 'rejected' },
            { new: true }
        );

        // If the assignment is not found, return an error response
        if (!assignment) {
            res.status(404).json({ error: 'Assignment not found' });
            return;
        }

        // Return a success response with the updated assignment details
        res.json({ message: 'Assignment rejected successfully', details: assignment });
    } catch (error) {
        // Handle errors during rejecting the assignment
        res.status(400).json({ error: 'Failed to reject assignment' });
    }
});
