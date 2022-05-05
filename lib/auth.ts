import jwt from "jsonwebtoken";
import { NextApiRequest, NextApiResponse } from "next";
import prisma from "./prisma";

export const validateRoute = (handler) => {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const { TRAX_ACCESS_TOKEN: token } = req.cookies;

    if (token) {
      let user;

      try {
        const { id } = jwt.verify(token, "jwt-secret");
        user = await prisma.user.findUnique({
          // db call is not necessary as we have valid JWT
          // but we're covering case that user ceased to exist while JWT was still valid
          where: { id },
        });

        if (!user) {
          throw new Error("User does not exist");
        }
      } catch (error) {
        // will return 401 for other errors
        res.status(401);
        res.json({ error: "Not authorized" });
        return;
      }
      handler(req, res, user);
    }

    res.status(401);
    res.json({ error: "Not authorized" });
  };
};
