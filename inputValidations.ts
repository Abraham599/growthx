import { z } from "zod";

export const LoginSchema = z.object({
    username: z.string().min(3).max(30),
    password: z.string().min(6),
  });
  
export const RegisterSchema = z.object({
    username: z.string().min(3).max(30),
    password: z.string().min(6),
    confirmPassword: z.string().min(6)
  });
  
  
export const AssignmentSchema = z.object({
      task: z.string(),
      admin: z.string().min(3).max(30)
  });