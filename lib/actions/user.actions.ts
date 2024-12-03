"use server";

import { createAdminClient, createSessionClient } from "@/lib/appwrite";
import { appwriteConfig } from "@/lib/appwrite/config";
import { Query, ID } from "node-appwrite";
import { parseStringify } from "@/lib/utils";
import { cookies } from "next/headers";
import { avatarPlaceholderUrl } from "@/constants";
import { parse } from "path";
import { redirect } from "next/navigation";

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
				avatar: avatarPlaceholderUrl,
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

export const getCurrentUser = async () => {
	const { account, databases } = await createSessionClient();
	const result = await account.get();
	const user = await databases.listDocuments(
		appwriteConfig.databaseId,
		appwriteConfig.usersCollectionId,
		[Query.equal("accountId", result.$id)]
	)

	if (user.total <= 0) return null;

	return parseStringify(user.documents[0]);
}

export const signOutUser = async () => {
	const { account } = await createSessionClient();

	try {
		await account.deleteSession("current");
		(await cookies()).delete("appwrite-session");
		console.log("User logged out successfully");
	} catch (error) {
		handleError(error, "Failed to sign out user");
	} finally {
		redirect("/sign-in");
	}
}

export const signInUser = async ({ email }: { email: string }) => {
	try {
		const existingUser = await getUserByEmail(email);
		if (existingUser) {
			await sendEmailOTP({ email });
			return parseStringify({ accountId: existingUser.accountId });
		}

		return parseStringify({ accountId: null, error: "User not found" });
	} catch (error) {
		handleError(error, "Failed to sign in user");
	}
}