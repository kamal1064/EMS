const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');

module.exports = function(passport) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL
      },
      async (accessToken, refreshToken, profile, done) => {
        const primaryEmail = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
        const profileAvatar = profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null;

        if (!primaryEmail) {
          return done(new Error('No email found associated with this Google account.'), null);
        }

        const newUser = {
          googleId: profile.id,
          name: profile.displayName,
          email: primaryEmail,
          avatar: profileAvatar,
          lastLogin: new Date()
        };

        try {
          // 1. Try to find user by their googleId
          let user = await User.findOne({ googleId: profile.id });

          if (user) {
            // User exists, update lastLogin and avatar dynamically
            user.lastLogin = new Date();
            user.avatar = profileAvatar || user.avatar;
            await user.save();
            return done(null, user);
          }

          // 2. Fallback: Find user by email (in case they were pre-registered by email)
          user = await User.findOne({ email: primaryEmail });

          if (user) {
            // Associate googleId with existing email account
            user.googleId = profile.id;
            user.avatar = profileAvatar || user.avatar;
            user.lastLogin = new Date();
            await user.save();
            return done(null, user);
          }

          // 3. User does not exist, create a new record
          // The first user created in the DB gets 'Admin' role automatically for convenience, others get 'Employee'
          const userCount = await User.countDocuments({});
          if (userCount === 0) {
            newUser.role = 'Admin';
          }

          user = await User.create(newUser);
          return done(null, user);
        } catch (err) {
          console.error('Passport Auth Verification Error:', err);
          return done(err, null);
        }
      }
    )
  );

  // Serialize user ID to save in session cookie
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  // Deserialize user ID on subsequent requests to retrieve full user object
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
};
