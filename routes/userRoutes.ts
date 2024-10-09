import express from 'express';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { User } from '../models/userModel';
import { authenticateToken } from '../middleware/auth';
import { Assignment } from '../models/assignmentModel';
import { JWT_SECRET } from '../config';
import bcrypt from 'bcryptjs';
import { AssignmentSchema, LoginSchema, RegisterSchema } from '../inputValidations';

// Create a new Express Router instance for user-related routes
export const userRouter = express.Router();

// Route to handle user registration
userRouter.post('/register', async (req, res) => {
  try {
      // Validate input data using RegisterSchema
      const userData = RegisterSchema.safeParse(req.body);
      if(!userData.success){
          res.status(411).json({
              message: "Incorrect inputs"
          });
          return;
      }

      const { username, password, confirmPassword } = userData.data;

      // Check if password and confirmPassword match
      if(password !== confirmPassword){
          res.status(411).json({
              message: "Please confirm the desired password you have entered"
          });
          return;
      }

      // Check if the user already exists in the system
      const existingUser = await User.findOne({
          username: username,
          role: "user"
      });
      
      if (existingUser) {
          res.status(411).json({
              message: "Username already taken. Use a different username"
          });
          return;
      }
      
      // Create a new user
      const user = await User.create({
          username: username,
          password: password,
          role: "user"
      });

      const userId = user._id;

      // Generate a JWT token for the new user
      const token = jwt.sign({
        userId
    }, JWT_SECRET);

      res.status(201).json({ token, message: 'User registered successfully' });
  } catch (error) {
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

// Route to handle user login
userRouter.post('/login', async (req, res) => {
    try {
        // Validate input data using LoginSchema
        const userData = LoginSchema.safeParse(req.body);
        if(!userData.success){
            res.status(411).json({
                message: "Incorrect inputs"
            });
            return;
        }

        const { username, password } = userData.data;

        // Check if the user exists
        const existingUser = await User.findOne({
            username: username,
            role: "user"
        });

        if (!existingUser) {
            res.status(411).json({
                message: "User doesn't exist"
            });
            return;
        }

        // Verify if the entered password is correct
        const isPasswordValid = await bcrypt.compare(password, existingUser.password);

        if (!isPasswordValid) {
             res.status(401).json({
                message: "Invalid password"
            });
            return;
        }

        // Generate a JWT token for the authenticated user
        const token = jwt.sign({ userId: existingUser._id, role: existingUser.role }, JWT_SECRET);
        res.json({ token, message: "Welcome to GrowthX assignment portal!" });
    } catch (error) {
        if (error instanceof z.ZodError) {
            res.status(400).json({ error: error.errors });
        } else if(error instanceof Error) {
            res.status(400).json({ error: 'Login failed, check your request body format', details: error.message });
        } else {
          res.status(400).json({ error: 'An unknown error occurred during login' });
      }
    }
});

// Route to handle assignment uploads
userRouter.post('/upload', authenticateToken, async (req, res) => {
  try {
      console.log('req.user in upload route:', req.user);

      // Ensure the user is authenticated
      if (!req.user || !req.user.userId) {
          res.status(401).json({ error: 'User not authenticated properly' });
          return;
      }

      // Validate input data using AssignmentSchema
      const assignmentData = AssignmentSchema.safeParse(req.body);

      if (!assignmentData.success) {
          res.status(411).json({
              message: "Invalid form of input data."
          });
          return;
      }

      const { task, admin } = assignmentData.data;

      // Fetch the user details from the database
      const user = await User.findById(req.user.userId);
      console.log('Found user:', user);

      if (!user) {
          res.status(404).json({ error: 'User not found' });
          return;
      }

      // Fetch the admin details from the database
      const adminUser = await User.findOne({
          username: admin,
          role: "admin"
      });

      if (!adminUser) {
          res.status(411).json({
              message: "Admin does not exist or is not a valid admin"
          });
          return;
      }

      // Create a new assignment
      const assignment = await Assignment.create({
          userId: user._id,
          username: user.username,
          task: task,
          admin: adminUser.username,
      });
      
      res.status(201).json({ 
          message: 'Assignment uploaded successfully',
          assignment: {
              id: assignment._id,
              task: assignment.task,
              username: assignment.username,
              admin: assignment.admin,
              status: assignment.status,
              createdAt: assignment.createdAt
          }
      });
  } catch (error) {
      console.error('Error in upload route:', error);
      if (error instanceof z.ZodError) {
          res.status(400).json({ error: error.errors });
      } else if (error instanceof Error) {
          res.status(400).json({ error: 'Assignment upload failed', details: error.message });
      } else {
          res.status(400).json({ error: 'An unknown error occurred during assignment upload' });
      }
  }
});

// Route to get a list of all admins
userRouter.get('/admins', authenticateToken, async (req, res) => {
    try {
        // Fetch all admins (role: 'admin') from the database
        const admins = await User.find({ role: 'admin' }, 'username');
        if(admins.length === 0){
          res.json({message: "No admin exists in the portal"});
          return;
        }
        res.json(admins);
       
    } catch (error) {
        res.status(400).json({ error: 'Failed to fetch admins' });
    }
});
