const bcrypt = require('bcryptjs');
const { webcrypto } = require('node:crypto');
const { SystemRoles, errorsToString } = require('librechat-data-provider');
const { createClient } = require('@supabase/supabase-js');
const {
  findUser,
  countUsers,
  createUser,
  updateUser,
  getUserById,
  generateToken,
  deleteUserById,
} = require('~/models/userMethods');
const { createToken, findToken, deleteTokens, Session } = require('~/models');
const { sendEmail, checkEmailConfig } = require('~/server/utils');
const { registerSchema } = require('~/strategies/validators');
const { hashToken } = require('~/server/utils/crypto');
const isDomainAllowed = require('./isDomainAllowed');
const { logger } = require('~/config');

const domains = {
  client: process.env.DOMAIN_CLIENT,
  server: process.env.DOMAIN_SERVER,
};

const isProduction = process.env.NODE_ENV === 'production';
const genericVerificationMessage = 'Please check your email to verify your email address.';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

const logoutUser = async (userId, refreshToken) => {
  try {
    const hash = await hashToken(refreshToken);
    const session = await Session.findOne({ user: userId, refreshTokenHash: hash });
    if (session) {
      await Session.deleteOne({ _id: session._id });
    }

    // Supabase logout
    const { error } = await supabase.auth.signOut();
    if (error) throw error;

    return { status: 200, message: 'Logout successful' };
  } catch (err) {
    return { status: 500, message: err.message };
  }
};

const createTokenHash = () => {
  const token = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString('hex');
  const hash = bcrypt.hashSync(token, 10);
  return [token, hash];
};

const sendVerificationEmail = async (user) => {
  const [verifyToken, hash] = createTokenHash();
  const verificationLink = `${domains.client}/verify?token=${verifyToken}&email=${encodeURIComponent(user.email)}`;
  await sendEmail({
    email: user.email,
    subject: 'Verify your email',
    payload: {
      appName: process.env.APP_TITLE || 'LibreChat',
      name: user.name,
      verificationLink: verificationLink,
      year: new Date().getFullYear(),
    },
    template: 'verifyEmail.handlebars',
  });
  await createToken({
    userId: user._id,
    email: user.email,
    token: hash,
    createdAt: Date.now(),
    expiresIn: 900,
  });
  logger.info(`[sendVerificationEmail] Verification link issued. [Email: ${user.email}]`);
};

const verifyEmail = async (req) => {
  const { email, token } = req.body;
  let emailVerificationData = await findToken({ email: decodeURIComponent(email) });
  if (!emailVerificationData) {
    logger.warn(`[verifyEmail] [No email verification data found] [Email: ${email}]`);
    return new Error('Invalid or expired password reset token');
  }
  const isValid = bcrypt.compareSync(token, emailVerificationData.token);
  if (!isValid) {
    logger.warn(`[verifyEmail] [Invalid or expired email verification token] [Email: ${email}]`);
    return new Error('Invalid or expired email verification token');
  }
  const updatedUser = await updateUser(emailVerificationData.userId, { emailVerified: true });
  if (!updatedUser) {
    logger.warn(`[verifyEmail] [User not found] [Email: ${email}]`);
    return new Error('User not found');
  }
  await deleteTokens({ token: emailVerificationData.token });
  logger.info(`[verifyEmail] Email verification successful. [Email: ${email}]`);
  return { message: 'Email verification was successful' };
};

const registerUser = async (user, additionalData = {}) => {
  const { error } = registerSchema.safeParse(user);
  if (error) {
    const errorMessage = errorsToString(error.errors);
    logger.info(
      'Route: register - Validation Error',
      { name: 'Request params:', value: user },
      { name: 'Validation error:', value: errorMessage },
    );
    return { status: 404, message: errorMessage };
  }

  const { email, password, name, username } = user;
  let newUserId;

  try {
    const existingUser = await findUser({ email }, 'email _id');
    if (existingUser) {
      logger.info(
        'Register User - Email in use',
        { name: 'Request params:', value: user },
        { name: 'Existing user:', value: existingUser },
      );
      await new Promise((resolve) => setTimeout(resolve, 1000));
      return { status: 200, message: genericVerificationMessage };
    }

    if (!(await isDomainAllowed(email))) {
      const errorMessage = 'The email address provided cannot be used. Please use a different email address.';
      logger.error(`[registerUser] [Registration not allowed] [Email: ${user.email}]`);
      return { status: 403, message: errorMessage };
    }

    const { data, error } = await supabase.auth.signUp({
      email: email,
      password: password
    });

    if (error) throw error;

    const isFirstRegisteredUser = (await countUsers()) === 0;
    const salt = bcrypt.genSaltSync(10);
    const newUserData = {
      provider: 'supabase',
      email,
      username,
      name,
      avatar: null,
      role: isFirstRegisteredUser ? SystemRoles.ADMIN : SystemRoles.USER,
      password: bcrypt.hashSync(password, salt),
      emailVerified: true,
      ...additionalData,
    };

    const newUser = await createUser(newUserData, false, true);
    newUserId = newUser._id;

    return { status: 200, message: genericVerificationMessage };
  } catch (err) {
    logger.error('[registerUser] Error in registering user:', err);
    if (newUserId) {
      const result = await deleteUserById(newUserId);
      logger.warn(
        `[registerUser] [Email: ${email}] [Temporary User deleted: ${JSON.stringify(result)}]`,
      );
    }
    return { status: 500, message: 'Something went wrong' };
  }
};

const requestPasswordReset = async (req) => {
  const { email } = req.body;

  try {
    const { data, error } = await supabase.auth.resetPasswordForEmail(email);
    if (error) throw error;

    return { message: 'If an account with that email exists, a password reset link has been sent to it.' };
  } catch (error) {
    logger.error('[requestPasswordReset] Error:', error);
    return { message: 'If an account with that email exists, a password reset link has been sent to it.' };
  }
};

const resetPassword = async (userId, token, password) => {
  try {
    const { data, error } = await supabase.auth.updateUser({ password });
    if (error) throw error;

    // Update local user password
    const hash = bcrypt.hashSync(password, 10);
    await updateUser(userId, { password: hash });

    return { message: 'Password reset was successful' };
  } catch (error) {
    logger.error('[resetPassword] Error:', error);
    return new Error('Invalid or expired password reset token');
  }
};

const setAuthTokens = async (userId, res, sessionId = null) => {
  try {
    const user = await getUserById(userId);
    const token = await generateToken(user);
    let session;
    let refreshTokenExpires;

    if (sessionId) {
      session = await Session.findById(sessionId);
      refreshTokenExpires = session.expiration.getTime();
    } else {
      session = new Session({ user: userId });
      const { REFRESH_TOKEN_EXPIRY } = process.env ?? {};
      const expires = eval(REFRESH_TOKEN_EXPIRY) ?? 1000 * 60 * 60 * 24 * 7;
      refreshTokenExpires = Date.now() + expires;
    }

    const refreshToken = await session.generateRefreshToken();
    res.cookie('refreshToken', refreshToken, {
      expires: new Date(refreshTokenExpires),
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
    });

    return token;
  } catch (error) {
    logger.error('[setAuthTokens] Error in setting authentication tokens:', error);
    throw error;
  }
};

const resendVerificationEmail = async (req) => {
  try {
    const { email } = req.body;
    await deleteTokens(email);
    const user = await findUser({ email }, 'email _id name');
    if (!user) {
      logger.warn(`[resendVerificationEmail] [No user found] [Email: ${email}]`);
      return { status: 200, message: genericVerificationMessage };
    }

    const [verifyToken, hash] = createTokenHash();
    const verificationLink = `${domains.client}/verify?token=${verifyToken}&email=${encodeURIComponent(user.email)}`;
    await sendEmail({
      email: user.email,
      subject: 'Verify your email',
      payload: {
        appName: process.env.APP_TITLE || 'LibreChat',
        name: user.name,
        verificationLink: verificationLink,
        year: new Date().getFullYear(),
      },
      template: 'verifyEmail.handlebars',
    });
    await createToken({
      userId: user._id,
      email: user.email,
      token: hash,
      createdAt: Date.now(),
      expiresIn: 900,
    });
    logger.info(`[resendVerificationEmail] Verification link issued. [Email: ${user.email}]`);
    return { status: 200, message: genericVerificationMessage };
  } catch (error) {
    logger.error(`[resendVerificationEmail] Error resending verification email: ${error.message}`);
    return { status: 500, message: 'Something went wrong.' };
  }
};

const loginWithSupabase = async (email, password) => {
  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) throw error;

    let user = await findUser({ email }, 'email _id');

    if (!user) {
      const randomPassword = Math.random().toString(36).slice(-8);
      const salt = bcrypt.genSaltSync(10);
      const newUserData = {
        provider: 'supabase',
        email,
        password: bcrypt.hashSync(randomPassword, salt),
        emailVerified: true,
      };
      user = await createUser(newUserData, false, true);
    }

    const token = await setAuthTokens(user._id, res);
    return { status: 200, message: 'Login successful', token };
  } catch (error) {
    logger.error('[loginWithSupabase] Error:', error);
    return { status: 401, message: 'Invalid credentials' };
  }
};

module.exports = {
  logoutUser,
  verifyEmail,
  registerUser,
  setAuthTokens,
  resetPassword,
  isDomainAllowed,
  requestPasswordReset,
  resendVerificationEmail,
  loginWithSupabase,
};