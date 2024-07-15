import { Request, Response, Router } from 'express';
import { User } from '../entities/User';
import { isEmpty, validate } from 'class-validator';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';

const mapError = (errors: Object[]) => {
  return errors.reduce((prev: any, err: any) => {
    prev[err.property] = Object.entries(err.constraints)[0][1];
    return prev;
  }, {});
};

const register = async (req: Request, res: Response) => {
  const { email, password, username } = req.body;

  try {
    let errors: any = {};

    // Check if email and username are already in use
    const emailUser = await User.findOneBy({ email });
    const usernameUser = await User.findOneBy({ username });

    // If they exist, add to the errors object
    if (emailUser) errors.email = 'This email address is already in use.';
    if (usernameUser) errors.username = 'This username is already in use.';

    // If there are errors, return an error response
    if (Object.keys(errors).length > 0) {
      return res.status(400).json(errors);
    }

    const user = new User();
    user.email = email;
    user.username = username;
    user.password = password;

    // validation check, what in entity already declared
    errors = await validate(user);

    if (errors.length > 0) return res.status(400).json(mapError(errors));

    await user.save();

    return res.json(user);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error });
  }
};

const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;
  try {
    let errors: any = {};

    // If empty, send errors to the client side
    if (isEmpty(username)) errors.username = 'Username cannot be empty.';
    if (isEmpty(password)) errors.password = 'Password cannot be empty.';

    if (Object.keys(errors).length > 0) {
      return res.status(400).json(errors);
    }

    // find user from DB
    const user = await User.findOneBy({ username });

    if (!user)
      return res
        .status(404)
        .json({ username: '사용자 이름이 등록되지 않았습니다.' });

    // 유저가 있다면 비밀번호 비교하기
    const passwordMatches = await bcrypt.compare(password, user.password);

    // 비밀번호가 다르다면 에러 보내기
    if (!passwordMatches) {
      return res.status(401).json({ password: '비밀번호가 잘못되었습니다.' });
    }

    // 비밀번호가 맞다면 토큰 생성
    const token = jwt.sign({ username }, process.env.JWT_SECRET);

    // 쿠키 저장
    res.set(
      'Set-Cookie',
      cookie.serialize('token', token, {
        httpOnly: true,
        maxAge: 60 * 60 * 24 * 7,
        path: '/',
      }),
    );

    return res.json({ user, token });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error });
  }
};

const router = Router();
router.post('/register', register);
router.post('/login', login);

export default router;
