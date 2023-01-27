import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

type Response = {
  statusCode: number;
  body: string;
};

export class Auth {
  public static async validateJwt(
    token: string | undefined,
    jwksUri: string,
    audience: string
  ): Promise<Response | undefined> {
    if (!token)
      return this.createResponse(
        "Bearer token missing from Authorization header"
      );

    var client = jwksClient({
      jwksUri: jwksUri,
    });

    // Multiple signing keys can be used, so we have to find the correct one
    // based on the 'kid' in the token header
    const decodedToken = jwt.decode(token, { complete: true });

    if (decodedToken === null)
      return this.createResponse("Unable to decode token");

    const kid = decodedToken?.header.kid;
    const alg = decodedToken?.header.alg;

    if (kid === undefined || alg === undefined)
      return this.createResponse(
        `Kid ${kid} or Alg ${alg} not found in token headers`
      );

    const signingKeys = await client.getSigningKeys();

    const signingKey = signingKeys.find((key) => key.kid === kid);

    if (signingKey === undefined)
      return this.createResponse(`Signing key for kid ${kid} not found`);

    const publicSigningKey = signingKey.getPublicKey();

    jwt.verify(token, publicSigningKey, {
      algorithms: [alg as jwt.Algorithm],
      audience: audience,
    });

    return undefined;
  }

  private static createResponse(body: string) {
    return {
      statusCode: 401,
      body: body,
    };
  }
}
