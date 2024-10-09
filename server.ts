import mongoose from 'mongoose';
import express from 'express';
import bodyParser from 'body-parser';
import rootRouter from './routes/index';

// MongoDB connection string

mongoose.connect('<your-mongodb-connection-string>')
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));


const app = express();
const PORT = 3000;

app.use(bodyParser.json());


app.use("/api", rootRouter); // /api/..

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});