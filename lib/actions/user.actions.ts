"use server";

import { createAdminClient } from "@/lib/appwrite";
import { appwriteConfig } from "@/lib/appwrite/config";
import { Query, ID } from "node-appwrite";
import { parseStringify } from "@/lib/utils";
import { cookies } from "next/headers";

// Create account flow
// 1. User enters full name and email
// 2. Check if the user already exist using the email (we will use this to identify if we still need to create a user document or not)
// 3. send OTP to the email
// 4. this will send a secret key for creating a session. (The Secret key or OTP will be sent to the user's account mail)
// 5. Create a new user document if the user is a new user
// 6. Return the user account id that would be used to complete the login process later with the OTP
// 7. verify OTP and authenticate to login

const handleError = (error: unknown, message: string) => {
	console.log(error, message);
	throw error;
};

const getUserByEmail = async (email: string) => {
	const { databases } = await createAdminClient();

	const result = await databases.listDocuments(
		appwriteConfig.databaseId,
		appwriteConfig.usersCollectionId,
		[Query.equal("email", [email])]
	);

	return result.total > 0 ? result.documents[0] : null;
};

export const sendEmailOTP = async ({ email }: { email: string }) => {
	const { account } = await createAdminClient();

	try {
		const session = await account.createEmailToken(ID.unique(), email);
		return session.userId;
	} catch (error) {
		handleError(error, "Failed to send email OTP");
	}
};

type createAccountSchema = {
	fullName: string;
	email: string;
};

/**
 * Creates a new user account.
 *
 * This function checks if a user with the given email already exists. If the user does not exist,
 * it sends an OTP to the provided email and creates a new user document in the database.
 *
 * @param {Object} params - The parameters for creating an account.
 * @param {string} params.fullName - The full name of the user.
 * @param {string} params.email - The email address of the user.
 * @returns {Promise<string>} The account ID as a string.
 * @throws {Error} If sending the OTP fails.
 */
export const createAccount = async ({
	fullName,
	email,
}: createAccountSchema) => {
	const existingUser = await getUserByEmail(email);

	const accountId = await sendEmailOTP({ email });
	if (!accountId) throw new Error("Failed to send an OTP");

	if (!existingUser) {
		const { databases } = await createAdminClient();

		await databases.createDocument(
			appwriteConfig.databaseId,
			appwriteConfig.usersCollectionId,
			ID.unique(),
			{
				fullName,
				email,
				avatar: "https://th.bing.com/th/id/OIP.hGSCbXlcOjL_9mmzerqAbQHaHa?w=181&h=181&c=7&r=0&o=5&pid=1.7",
				accountId,
			}
		);
	}

	return parseStringify({ accountId });
};

export const verifySecret = async ({
	accountId,
	password,
}: {
	accountId: string;
	password: string;
}) => {
	try {
		const { account } = await createAdminClient();
		const session = await account.createSession(accountId, password);

		(await cookies()).set("appwrite-session", session.secret, {
			path: "/",
			httpOnly: true,
			sameSite: "strict",
			secure: true,
		});

		return parseStringify({ sessionId: session.$id });
	} catch (error) {
		handleError(error, "Failed to verify OTP");
	}
};
