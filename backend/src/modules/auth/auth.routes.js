import { Router } from "express";
import {
  login,
  loginValidation,
  register,
  createUserValidation,
  logout,
  changePassword,
  changePasswordValidation,
  updateUser,
  updateUserValidation,
} from "./auth.controller.js";
import { authenticate, isAdmin } from "../../middlewares/auth.middleware.js";

const router = Router();

// POST /api/auth/login
router.post("/login", loginValidation, login);

// POST /api/auth/register — solo admin
router.post("/register", authenticate, isAdmin, createUserValidation, register);

// POST /api/auth/logout — cualquier usuario autenticado
router.post("/logout", authenticate, logout);

// PUT /api/auth/change-password — cualquier usuario autenticado
router.put(
  "/change-password",
  authenticate,
  changePasswordValidation,
  changePassword,
);

// PUT /api/auth/users/:id — solo admin
router.put(
  "/users/:id",
  authenticate,
  isAdmin,
  updateUserValidation,
  updateUser,
);

export default router;
