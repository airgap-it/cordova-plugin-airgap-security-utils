//
//  SecureStorage.swift
//  SecureStorage
//
//  Created by Alessandro De Carli on 23.02.18.
//  Copyright © 2018 ___Alessandro De Carli___. All rights reserved.
//

import Foundation
import Security
import LocalAuthentication

public class SecureStorage {

    let tag: Data
    let accessControlFlags: SecAccessControlCreateFlags
	private var secretKeyQuery: [String: Any] {
		return [
			kSecClass as String: kSecClassKey,
			kSecAttrApplicationTag as String: tag,
			kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
			kSecReturnRef as String: true
		]
	}

	public init(tag: Data, paranoiaMode: Bool = false){
        self.tag = tag
        if (paranoiaMode){
            accessControlFlags = [.privateKeyUsage, .userPresence, .applicationPassword]
        } else {
            accessControlFlags = [.privateKeyUsage, .userPresence]
        }
    }

    @inline(__always) private func generateNewBiometricSecuredKey() throws -> SecKey {
		var error: Unmanaged<CFError>? = nil
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, accessControlFlags, &error) else {
			throw Error(error?.autorelease().takeUnretainedValue())
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ]
        ]
        
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
			throw Error(error?.autorelease().takeUnretainedValue())
        }
        
        return privateKey
    }

	private func fetchBiometricSecuredKey(completion: @escaping (Result<SecKey, Error>) -> ()) {
		LocalAuthentication.shared.authenticateAccess(for: .useItem) { result in
			switch result {
			case let .success((_, context)):
				self.fetchKey(using: context, completion: completion)
			case let .failure(error):
				completion(.failure(Error(error)))
			}
		}
	}

	@inline(__always) func fetchKey(using context: LAContext, completion: @escaping (Result<SecKey, Error>) -> ()) {
		DeviceIntegrity.assess { result in
			guard result == .ok else {
				completion(.failure(.diar(result)))
				return
			}
			var item: CFTypeRef?
			var query = self.secretKeyQuery
			query[kSecUseAuthenticationContext as String] = context
			let status = SecItemCopyMatching(query as CFDictionary, &item)
			guard status == errSecSuccess, let key = item else {
				do {
					let key = try self.generateNewBiometricSecuredKey()
					completion(.success(key))
				} catch {
					completion(.failure(Error(error)))
				}
				return
			}
			completion(.success(key as! SecKey))
		}
	}
    
    public func dropSecuredKey() -> Bool {
        let status = SecItemDelete(secretKeyQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { return false }
        return true
    }

	public func store(key: String, value: String, completion: @escaping (Error?) -> ()) {
		fetchBiometricSecuredKey { result in
			switch result {
			case let .success(secretKey):
				DeviceIntegrity.assess() { result in
					guard result == .ok else {
						completion(.diar(result))
						return
					}
					do {
						try self.store(key: key, value: value, using: secretKey)
						completion(nil)
					} catch {
						completion(Error(error))
					}
				}
			case let .failure(error):
				completion(Error(error))
			}
		}
    }

	private func store(key: String, value: String, using secretKey: SecKey) throws {
		guard let eCCPublicKey = SecKeyCopyPublicKey(secretKey) else {
			throw Error.pubKeyCopyFailure
		}

		guard let messageData = value.data(using: .utf8) else {
			throw Error.dataConversionFailure
		}

		var error: Unmanaged<CFError>? = nil
		guard let encryptedData = SecKeyCreateEncryptedData(eCCPublicKey, .eciesEncryptionStandardX963SHA256AESGCM, messageData as CFData, &error) else {
			throw Error(error?.autorelease().takeUnretainedValue())
		}

		let addKeyChainAttributes: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrAccount as String: key,
			kSecValueData as String: encryptedData
		]
		var status = SecItemAdd(addKeyChainAttributes as CFDictionary, nil)
		if status == errSecDuplicateItem {
			let queryParameters: [String: Any] = [
				kSecClass as String: kSecClassGenericPassword,
				kSecAttrAccount as String: key
			]
			let updateKeyChainAttributes: [String: Any] = [kSecValueData as String: encryptedData]
			status = SecItemUpdate(queryParameters as CFDictionary, updateKeyChainAttributes as CFDictionary)
		}
		guard status == errSecSuccess || status == errSecItemNotFound else {
			throw Error.osStatus(status)
		}
	}

	public func retrieve(key: String, completion: @escaping (Result<String, Error>) -> ()) {
		fetchBiometricSecuredKey { result in
			switch result {
			case let .success(secretKey):
				DeviceIntegrity.assess() { result in
					guard result == .ok else {
						completion(.failure(.diar(result)))
						return
					}
					do {
						let value = try self.retrieve(key: key, using: secretKey)
						completion(.success(value))
					} catch {
						completion(.failure(Error(error)))
					}
				}
			case let .failure(error):
				completion(.failure(Error(error)))
			}
		}
	}
    
	private func retrieve(key: String, using secretKey: SecKey) throws -> String {
        var item: CFTypeRef?
        let queryParameters: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrAccount as String: key,
			kSecReturnData as String: true
		]
        let status = SecItemCopyMatching(queryParameters as CFDictionary, &item)
        guard status == errSecSuccess else {
			throw Error.osStatus(status)
		}

		var error: Unmanaged<CFError>? = nil
        guard let decryptedData = SecKeyCreateDecryptedData(secretKey, .eciesEncryptionStandardX963SHA256AESGCM, item as! CFData, &error) else {
			throw Error(error?.autorelease().takeUnretainedValue())
        }
        
		guard let result = String(data: decryptedData as Data, encoding: .utf8) else {
			throw Error.stringConversionFailure
		}

		return result
    }

	public func delete(key: String) throws {
		let queryParameters: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrAccount as String: key,
			kSecReturnData as String: true
		]
		let status = SecItemDelete(queryParameters as CFDictionary)

		guard status == errSecSuccess else {
			throw Error.osStatus(status)
		}
	}

	public enum Error: Swift.Error {
		case unknown
		case `internal`(Swift.Error)
		case pubKeyCopyFailure
		case dataConversionFailure
		case stringConversionFailure
		case osStatus(OSStatus)
		case diar(DeviceIntegrity.ResultSet)

		init(_ error: Swift.Error?) {
			if let error = error as? Error {
				self = error
			} else if let error = error {
				self = .internal(error)
			} else {
				self = .unknown
			}
		}
	}
}
