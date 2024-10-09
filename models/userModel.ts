import mongoose, { Document, Schema } from 'mongoose';
import bcrypt from 'bcryptjs';

export interface UserDocument extends Document {
  username: string;
  password: string;
  role: 'user' | 'admin';
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema: Schema<UserDocument> = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minLength: 3,
    maxLength: 30
  },
  password: {
    type: String,
    required: true,
    minLength: 6
  },
  role: { 
    type: String, 
    enum: ['user', 'admin'], 
    default: 'user' 
  }
});

// The below lines of code saves the encrypted version of the password

userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});


export const User = mongoose.model<UserDocument>('User', userSchema);

