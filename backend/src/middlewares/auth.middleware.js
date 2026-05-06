import jwt from "jsonwebtoken";

export const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ ok: false, error: "Token requerido" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res
      .status(401)
      .json({ ok: false, error: "Token inválido o expirado" });
  }
};

export const isAdmin = (req, res, next) => {
  if (req.user.role !== 1) {
    return res
      .status(403)
      .json({ ok: false, error: "No tienes permisos para esta acción" });
  }
  next();
};
