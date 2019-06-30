//
//  LocalAuthentication.swift
//  AGUtilities
//
//  Created by Mike Godenzi on 25.06.19.
//  Copyright © 2019 Mike Godenzi. All rights reserved.
//

import Foundation
import LocalAuthentication

public class LocalAuthentication {

	public static let shared = LocalAuthentication()
	private static var automaticKey = "local_auth_automatic"
	private static var authenticationReasonKey = "local_auth_reason"
	private static var defaultAuthenticationReason = "Please authenticate to continue to use the app."

	private lazy var context: LAContext = {
		let result = LAContext()
		result.localizedReason = self.localizedAuthenticationReason
		return result
	}()
	private var queue: OperationQueue = {
		let result = OperationQueue()
		result.maxConcurrentOperationCount = 1
		result.name = "ch.papers.security-utils.LocalAuthentication"
		return result
	}()
	private var lastAuthentication: Date = .distantFuture
	private var lastBackground: Date?
	public var invalidateAfter: TimeInterval = 10
	public fileprivate(set) var isAuthenticated = false

	private var defaults: UserDefaults {
		return UserDefaults.standard
	}
	public var automatic: Bool {
		get {
			return defaults.bool(forKey: LocalAuthentication.automaticKey)
		}
		set {
			defer {
				updateAutomaticAuthenticationIfNeeded()
			}
			let current = self.automatic
			guard current != newValue else {
				return
			}
			defaults.set(newValue, forKey: LocalAuthentication.automaticKey)
		}
	}
	public var localizedAuthenticationReason: String {
		get {
			return defaults.string(forKey: LocalAuthentication.authenticationReasonKey) ?? LocalAuthentication.defaultAuthenticationReason
		}
		set {
			defaults.set(newValue, forKey: LocalAuthentication.authenticationReasonKey)
			context.localizedReason = newValue
		}
	}
	private var didBecomeActiveObserver: Observer?
	private var didEnterBackgroundObserver: Observer?

	private var needsAccessInvalidation: Bool {
		let now = Date()
		return now > lastAuthentication.addingTimeInterval(invalidateAfter)
	}
	private var needsAuthenticationInvalidation: Bool {
		guard let lastBackground = self.lastBackground else {
			return false
		}
		let now = Date()
		return now > lastBackground.addingTimeInterval(invalidateAfter)
	}

	public func fetchContextForAccessAuthentication(_ authenticationHandler: @escaping (LAContext) -> Bool) {
		let operation = BlockOperation {
			if authenticationHandler(self.context) {
				self.lastAuthentication = Date()
				self.isAuthenticated = true
			}
		}
		operation.addDependency(InvalidateOperation(localAuth: self, condition: self.needsAccessInvalidation))
		enqueue(operation)
	}

	public func authenticate(localizedReason reason: String? = nil, completion: @escaping (Result<Bool, Error>) -> ()) {
		let operation = AuthenticationOperation(localAuth: self)
		operation.localizedReason = reason ?? context.localizedReason
		let invalidate = InvalidateOperation(localAuth: self, condition: self.needsAuthenticationInvalidation)
		operation.addDependency(invalidate)
		operation.completionBlock = { [unowned operation] in
			guard operation.error == nil else {
				completion(.failure(Error(operation.error)))
				return
			}
			completion(.success(operation.result))
		}
		enqueue(operation)
	}

	public func invalidate(completion: @escaping () -> ()) {
		let operation = InvalidateOperation(localAuth: self, condition: true)
		operation.completionBlock = completion
		queue.addOperation(operation)
	}

	public func setInvalidationTimeout(_ timeout: TimeInterval) {
		queue.addOperation {
			self.invalidateAfter = timeout
		}
	}

	public func updateAutomaticAuthenticationIfNeeded() {
		if automatic && didBecomeActiveObserver == nil {
			didBecomeActiveObserver = Observer(name: UIApplication.didBecomeActiveNotification, object: UIApplication.shared) { [unowned self] _ in
				self.authenticate() { result in
					if case let .failure(error) = result {
						print(error)
					}
				}
			}
			didEnterBackgroundObserver = Observer(name: UIApplication.didEnterBackgroundNotification, object: UIApplication.shared, queue: queue) { [unowned self] _ in
				self.lastBackground = Date()
			}
		} else if !automatic && didBecomeActiveObserver != nil {
			didBecomeActiveObserver = nil
			didEnterBackgroundObserver = nil
		}
	}

	private func enqueue(_ operation: Operation) {
		for dependent in operation.dependencies where !dependent.isFinished && !dependent.isExecuting {
			queue.addOperation(dependent)
		}
		queue.addOperation(operation)
	}

	public enum Error: Swift.Error {
		case unknown
		case `internal`(Swift.Error)
		case cancelled

		init(_ error: Swift.Error?) {
			if let error = error {
				self = .internal(error)
			} else {
				self = .unknown
			}
		}
	}

	class AsyncOperation: Operation {

		override open var isAsynchronous: Bool {
			return true
		}

		private var _isExecuring: Bool = false
		private static let isExecutingKey = "isExecuting"
		override open var isExecuting: Bool {
			get {
				return _isExecuring
			}
			set {
				willChangeValue(forKey: AsyncOperation.isExecutingKey)
				_isExecuring = newValue
				didChangeValue(forKey: AsyncOperation.isExecutingKey)
			}
		}

		private var _isFinished: Bool = false
		private static let isFinishedKey = "isFinished"
		override open var isFinished: Bool {
			get {
				return _isFinished
			}
			set {
				willChangeValue(forKey: AsyncOperation.isFinishedKey)
				_isFinished = newValue
				didChangeValue(forKey: AsyncOperation.isFinishedKey)
			}
		}

		var error: Error?

		override func start() {
			guard !isCancelled else {
				return
			}

			isExecuting = true

			perform {
				self.stop()
			}
		}

		func perform(completion: @escaping () -> ()) {
			completion()
		}

		override open func cancel() {
			if error == nil {
				error = .cancelled
			}
			super.cancel()
			stop()
		}

		func cancel(with error: Error) {
			self.error = error
			self.cancel()
		}

		private func stop() {
			if !isFinished {
				isFinished = true
			}
			if isExecuting {
				isExecuting = false
			}
		}
	}

	class AuthenticationOperation: AsyncOperation {

		unowned let localAuth: LocalAuthentication
		var context: LAContext {
			return localAuth.context
		}
		var policy: LAPolicy = .deviceOwnerAuthentication
		var localizedReason: String = "Please authenticate"
		private(set) var result: Bool = false

		init(localAuth: LocalAuthentication) {
			self.localAuth = localAuth
		}

		override func perform(completion: @escaping () -> ()) {
			guard !localAuth.isAuthenticated else {
				result = true
				self.localAuth.lastBackground = nil
				completion()
				return
			}
			context.evaluatePolicy(policy, localizedReason: localizedReason) { (result, error) in
				self.result = result
				self.error = (error != nil) ? Error(error) : nil
				if result {
					self.localAuth.lastAuthentication = Date()
					self.localAuth.isAuthenticated = true
				}
				self.localAuth.lastBackground = nil
				completion()
			}
		}
	}

	class InvalidateOperation: Operation {

		unowned let localAuth: LocalAuthentication
		private let condition: () -> Bool

		init(localAuth: LocalAuthentication, condition: @escaping @autoclosure () -> Bool) {
			self.condition = condition
			self.localAuth = localAuth
		}

		override func main() {
			if condition() {
				let context = LAContext()
				context.localizedReason = localAuth.localizedAuthenticationReason
				localAuth.context.invalidate()
				localAuth.context = context
				localAuth.isAuthenticated = false
			}
		}
	}
}
