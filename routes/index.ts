import express from 'express';
import { userRouter } from './userRoutes';
import { adminRouter } from './adminRoutes';

const router = express.Router();

router.use("/user", userRouter);  // /user/.. routes
router.use("/admin", adminRouter); // /admin/.. routes

export default router;