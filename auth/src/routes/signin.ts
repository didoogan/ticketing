import express, {Request, Response} from 'express';
import {body} from 'express-validator';
import jwt from 'jsonwebtoken';

import {User} from '../models/user';
import {validateRequest} from '@doogan-tickets/common';
import {BadRequestError} from '@doogan-tickets/common';
import {Password} from '../services/password';

const router = express.Router();

router.post('/api/users/signin',
	[
		body('email')
			.isEmail()
			.withMessage('Email must be valid'),
	  body('password')	
			.trim()
			.notEmpty()
			.withMessage('You must supply a password')
	],
	validateRequest,
	async (req: Request, res:Response) => {
    const {email, password} = req.body;
		const existedUser = await User.findOne({email});
    
		if (!existedUser) {
			console.log('Unexisted user');
			throw new  BadRequestError('Invalid credential provided');
		}
		
		const passwordMatch = await Password.compare(existedUser.password, password);
		
		if (!passwordMatch) {
			throw new  BadRequestError('Invalid credential provided');
		}
	// Generate JWT
	const existedUserJwt = jwt.sign({
		id: existedUser.id,
		email: existedUser.email
	}, process.env.JWT_KEY!);

	// Store it on session object
	req. session = {
		jwt: existedUserJwt
	};

	res.status(200).send(existedUser);

	}
);

export {router as signinRouter};

