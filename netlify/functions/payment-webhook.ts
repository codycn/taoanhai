import type { Handler, HandlerEvent } from "@netlify/functions";
import { supabaseAdmin } from './utils/supabaseClient';
import crypto from 'crypto';

const PAYOS_CHECKSUM_KEY = process.env.PAYOS_CHECKSUM_KEY;

// PayOS docs: The signature is created by sorting parameters alphabetically,
// joining them with '&', and then creating an HMAC-SHA256 hash.
const createSignature = (data: Record<string, any>, checksumKey: string): string => {
    const sortedKeys = Object.keys(data).sort();
    const dataString = sortedKeys.map(key => `${key}=${data[key]}`).join('&');
    return crypto.createHmac('sha256', checksumKey).update(dataString).digest('hex');
};

const handler: Handler = async (event: HandlerEvent) => {
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: JSON.stringify({ error: 'Method Not Allowed' }) };
    }

    const signatureFromHeader = event.headers['x-payos-signature'];
    const body = JSON.parse(event.body || '{}');

    // If the signature header is present, it's a genuine data webhook from PayOS that must be validated.
    if (signatureFromHeader) {
        console.log("--- [START] PayOS Payment Webhook Received ---");

        if (!PAYOS_CHECKSUM_KEY) {
            console.error('[FATAL] PAYOS_CHECKSUM_KEY is not set.');
            return { statusCode: 500, body: JSON.stringify({ error: 'Webhook configuration error.' }) };
        }
        
        try {
            const webhookData = body.data;
            if (!webhookData) {
                return { statusCode: 400, body: JSON.stringify({ error: 'Webhook data is missing.' }) };
            }
            
            const calculatedSignature = createSignature(webhookData, PAYOS_CHECKSUM_KEY);
            if (calculatedSignature !== signatureFromHeader) {
                console.warn(`[SECURITY_WARNING] Invalid signature.`);
                return { statusCode: 401, body: JSON.stringify({ error: 'Invalid signature.' }) };
            }
            console.log("[INFO] Signature validated successfully.");

            const { orderCode, status } = webhookData;
            const numericOrderCode = Number(orderCode);
            if (isNaN(numericOrderCode)) {
                return { statusCode: 400, body: JSON.stringify({ error: 'Invalid orderCode format.' }) };
            }
            
            const isSuccess = status?.toUpperCase() === 'PAID';
            const isFailure = status?.toUpperCase() === 'CANCELLED' || status?.toUpperCase() === 'FAILED';

            if (isSuccess) {
                // With manual approval, we just log this. The status remains 'pending'.
                console.log(`[INFO] Order ${numericOrderCode} is PAID. Awaiting admin approval.`);
            } else if (isFailure) {
                const dbStatus = status.toUpperCase() === 'CANCELLED' ? 'canceled' : 'failed';
                // Update the status for failed or canceled transactions
                await supabaseAdmin
                   .from('transactions')
                   .update({ status: dbStatus, updated_at: new Date().toISOString() })
                   .eq('order_code', numericOrderCode)
                   .eq('status', 'pending');
                console.log(`[INFO] Order ${numericOrderCode} marked as '${dbStatus}'.`);
            }

        } catch (error: any) {
            console.error(`[FATAL] Unhandled error in webhook data processing:`, error.message);
            return { statusCode: 500, body: JSON.stringify({ error: 'Internal server error.' }) };
        }

        console.log("--- [END] Webhook Processed Successfully ---");
        // Always return 200 OK to PayOS to prevent retries.
        return { statusCode: 200, body: JSON.stringify({ message: 'Webhook received.' }) };

    } else {
        // If there's NO signature header, it's a validation request (from our app or PayOS dashboard).
        // The correct response is 200 OK to indicate the URL is live.
        console.log("[INFO] Received a POST request without a signature. Treating as a validation request.");
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Webhook validation successful.' }),
        };
    }
};

export { handler };