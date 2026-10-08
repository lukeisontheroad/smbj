/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.smbj.connection;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.connection.packet.IncomingPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2SignatureVerificationPacketHandler;
import com.hierynomus.smbj.session.Session;

public class SignatureVerificationTest {

    @Test
    public void shouldDiscardAResponseWithAnInvalidSignatureAndDisconnect() throws Exception {
        // Signed STATUS_NO_MORE_FILES response, verified with the right key in PacketSignatoryTest.
        SMB2PacketData response = new SMB2PacketData(ByteArrayUtils.parseHex(
            "fe534d4240001000060000800e002000090000000000000015000000000000000000000001000000250000000024000046efdd50d6cdaa25bac7c4b5d49a0e08090000000000000005"));
        Session session = mock(Session.class);
        when(session.getSigningKey(any(), any(Boolean.class))).thenReturn(new SecretKeySpec(new byte[16], SMBSessionBuilder.HMAC_SHA256_ALGORITHM));
        SessionTable sessionTable = new SessionTable();
        sessionTable.registerSession(response.getHeader().getSessionId(), session);
        IncomingPacketHandler next = mock(IncomingPacketHandler.class);
        SMB2SignatureVerificationPacketHandler handler = new SMB2SignatureVerificationPacketHandler(sessionTable, new PacketSignatory(new BCSecurityProvider()));
        handler.setNext(next);

        // Thrown to the packet reader, which disconnects the connection (Connection.handleError).
        assertThrows(TransportException.class, () -> handler.handle(response));
        verifyNoInteractions(next);
    }
}
