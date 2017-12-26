var bcrypt = require('bcrypt');
import User from '../models/user.model';
import APIError from '../helpers/APIError';
import jwt from 'jsonwebtoken';
import config from '../config/config';
import httpStatus from 'http-status';
const nodemailer = require('nodemailer');

var forEach = require('async-foreach').forEach;

const saltRounds = 10;

/**
 * Load user and append to req.
 */
function load(req, res, next, id) {
  User.get(id)
    .then((user) => {
      req.user = user; // eslint-disable-line no-param-reassign
      return next();
    })
    .catch(e => next(e));
}

/**
 * Get user
 * @returns {User}
 */
function get (req, res) {
  return res.json(req.user);
}



/**
 * Create new user
 * @property {string} req.body.username - The username of user.
 * @property {string} req.body.mobileNumber - The mobileNumber of user.
 * @returns {User}
 */
function create(req, res, next) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    const user = new User({
      name: req.body.name,
      username: req.body.username,
      lastname: req.body.lastname,
      email: req.body.email,
      password: hash,
      gender: req.body.gender,
      dob: req.body.dob,
      phone_number: req.body.phone_number,
      freindRefferalCode:req.body.freindRefferalCode,
      RefferalUserId:req.body.RefferalUserId
    });

    user.save()
      .then(savedUser => res.json(savedUser))
      .catch(e => next(e));
  });

}

/**
 * Update existing user
 * @property {string} req.body.username - The username of user.
 * @property {string} req.body.mobileNumber - The mobileNumber of user.
 * @returns {User}
 */
function update(req, res, next) {
  const user = req.user;
  user.name = req.body.name;
  user.username = req.body.username;
  user.email = req.body.email;
  user.gender = req.body.gender;
  user.dob = req.body.dob;
  user.phone_number = req.body.phone_number;
  user.picture_name = req.body.picture_name;
  user.save()
    .then(savedUser => res.json(savedUser))
    .catch(e => next(e));
}

function updateLoyalityPoint(req, res, next){
  var user_id = req.body.user_id;
  console.log('user_id',user_id);
  User.get(user_id)
    .then((user) => {
    if(user.LoyalityPoints){
    user.LoyalityPoints = user.LoyalityPoints+10;
  }else{
    user.LoyalityPoints = 10;
  }
  user.save()
    .then(savedUser => res.json(savedUser))
.catch(e => next(e));

  })

}
/**
 * Get user list.
 * @property {number} req.query.skip - Number of user to be skipped.
 * @property {number} req.query.limit - Limit number of user to be returned.
 * @returns {User[]}
 */
function list(req, res, next) {
  const {limit = 50, skip = 0} = req.query;
  User.list({limit, skip})
    .then(users => res.json(users))
    .catch(e => next(e));
}

/**
 * Delete user.
 * @returns {User}
 */
function remove(req, res, next) {
  const user = req.user;
  user.remove()
    .then(deletedUser => res.json(deletedUser))
    .catch(e => next(e));
}


/**
 * Forgot Password.
 * @returns {User}
 */
function forgotPassowrd(req, res, next) {
  User.getUserByEmail(req.body.email)
    .then((user) => {
      const token = jwt.sign({
        email: req.body.email
      }, config.jwtSecret, { expiresIn: "1h" });

      let smtpConfig = {
        host: config.smtp.host,
        port: config.smtp.port,
        secure: true, // use SSL
        auth: {
          user: config.smtp.auth.user,
          pass: config.smtp.auth.pass
        }
      };
      let transporter = nodemailer.createTransport(smtpConfig);
      let resetUrl = "http://"+config.host+":"+config.port+"/admin/reset-password?verify="+token;
      // setup email data with unicode symbols
      let mailOptions = {
        from: 'seasia.php@gmail.com', // sender address
        to: user.email, // list of receivers
        subject: 'Password Reset', // Subject line
        //text: 'Hello world ?', // plain text body
        html: '<b>Reset your Password by clicking on </b> <a href='+resetUrl+'> Reset Password</a> . Link will expire in 1 hour' // html body
      };

      // send mail with defined transport object
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return console.log(error);
        }
        return res.json({ success: true, message: 'Please check your email for password reset instruction' });
      });

    })
    .catch(e => {
      {
        const err = new APIError('Invalid email', httpStatus.UNAUTHORIZED, true);
        return next(e);
      }
    });
}

/**
 * Veify token
 * @returns {User}
 */
function verifyToken(req, res, next) {
  console.log(req.query.token);
  var token = req.query.token;
  console.log('token');
  console.log(token);
  jwt.verify(token, config.jwtSecret , function(err, decoded) {
    if (err) {
      const err = new APIError("Token expired. Please request for password reset again", httpStatus.UNAUTHORIZED, true);
      return next(err);
      //return res.json({ success: false, message: 'Failed to authenticate token.' });
    } else {
      console.log('decoded');
      console.log(decoded);
      User.getUserByEmail(decoded.email)
        .then((user) => {
          return res.json({ success: true, message: 'Valid token.' });
        })
        .catch(e => {
          {
            const err = new APIError("Token expired. Please request for password reset again", httpStatus.UNAUTHORIZED, true);
            return next(err);
          }
        });
    }
  });

}

/**
 * Veify token
 * @returns {User}
 */
function updatePassword(req, res, next) {
  var token = req.query.token;
  jwt.verify(token, config.jwtSecret , function(err, decoded) {
    if (err) {
      const err = new APIError("Token expired. Please request for password reset again", httpStatus.UNAUTHORIZED, true);
      return next(err);
      //return res.json({ success: false, message: 'Failed to authenticate token.' });
    } else {
      User.getUserByEmail(decoded.email)
        .then((user) => {
          bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
            user.password = hash;
            user.save()
              .then(savedUser => res.json(savedUser))
              .catch(e => next(e));
          });
        })
        .catch(e => {
          {
            const err = new APIError("Token expired. Please request for password reset again", httpStatus.UNAUTHORIZED, true);
            return next(err);
          }
        });
    }
  });

}

function updateCustomerId(req, res, next) {
  User.updateCustomerId(req.body.userId, req.body.stripeCustomerId)
    .then(users => res.json(users))
    .catch(e => next(e));
}
function updateVirtualMoney(req, res, next) {
  User.updateVirtualMoney(req.body.userId, req.body.virtual_money)
    .then(users => res.json(users))
    .catch(e => next(e));
}

function getuserByRefferal(req, res, next) {
  var refferal_code = req.query.refferal_code;

  User.getUserByRefferalCode(refferal_code).then(user => res.json(user))
.catch(e => next(e));

}

/**
 * Verify old password
 * @returns {User}
 */
function verifyCurrentPassword(req, res, next) {
  var token = req.query.token;
  jwt.verify(token, config.jwtSecret , function(err, decoded) {
    if (err) {
      const err = new APIError("Token expired. Please request for password reset again", httpStatus.UNAUTHORIZED, true);
      return next(err);
      //return res.json({ success: false, message: 'Failed to authenticate token.' });
    } else {
      User.getUserByEmail(decoded.email)
        .then((user) => {
          let result = bcrypt.compareSync(req.body.current_password, user.password);
          return res.json(result);
        })
        .catch(e => {
          {
            const err = new APIError("Token expired. Please request for password reset again", httpStatus.UNAUTHORIZED, true);
            return next(err);
          }
        });
    }
  });
}

function sendRefferalEmail(req, res, next) {
  var data = JSON.parse(req.body.data);
  var freindRefferalCode = req.body.freindRefferalCode;
  var email = req.body.email;
  const token = jwt.sign({
    email: req.body.email
  }, config.jwtSecret, {expiresIn: "1h"});

  let smtpConfig = {
    host: config.smtp.host,
    port: config.smtp.port,
    secure: true, // use SSL
    auth: {
      user: config.smtp.auth.user,
      pass: config.smtp.auth.pass
    }
  };
  let transporter = nodemailer.createTransport(smtpConfig);
  var count = 1;

  let Url = config.siteUrl.url;

  forEach(data, function(item, index, arr) {

    let mailOptions = {
      from: email, // sender address
      to: item, // list of receivers
      subject: 'Refferal Code', // Subject line
      html: '<p>use the Refferal Code: <b>' + freindRefferalCode + '</b> for signUp in Littlecorner.</p><p>Link:<a href="'+Url+'">'+Url+'</a></p>' // html body
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);

        if (count == arr.length) {    // and then test if all done
          res.send({'result':'false','meassage':'There are some issue.'});
        }
      } else {
        console.log('Email sent: ' + info.response);
        if (count == arr.length) {    // and then test if all done
          res.send({'result':'true','meassage':'Email send successfully.'});
        }

      }
      count++;
    });

  });



}

function contactUs(req, res, next) {
  var subject = req.body.subject;
  var name = req.body.name;
  var from_email = req.body.email;
  var phone_number = req.body.phone_number;
  var message = req.body.message;



  User.getAdminUSer().then(function (user) {
    let email = user.email;
      var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'seasia.php@gmail.com',
          pass: 'qazwsx@321'
        }
      });

      var mailOptions = {
        from: from_email,
        to: email,
        subject: 'Contact Us',
        html: '<html><p>Hello,</p><p><b>Name: </b>'+name +'</p> <p><b>phone Number: </b>'+phone_number +'</p> <p><b>Subject: </b>'+subject +'</p> <p><b>Message:</b>'+ message+'</p><br><p></p></p></html>'
      };

      transporter.sendMail(mailOptions, function(error, info){
        if (error) {
          console.log(error);
          res.send(error);
        } else {
          console.log('Email sent: ' + info.response);
          res.send(info.response);
        }
      });


  })
}
export default {load, get, create, update, list, remove, forgotPassowrd, verifyToken, updatePassword, verifyCurrentPassword,getuserByRefferal, sendRefferalEmail,updateLoyalityPoint, updateCustomerId, updateVirtualMoney,contactUs};
