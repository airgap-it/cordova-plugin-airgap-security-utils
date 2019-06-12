//
//  SecureScreen.swift
//  AGUtilities
//
//  Created by Mike Godenzi on 07.06.19.
//  Copyright © 2019 Mike Godenzi. All rights reserved.
//

import Foundation
import UIKit

public final class SecureScreen {

	private static let storyboardNameKey = "UILaunchStoryboardName"

	private static let `default` = SecureScreen()

	private var outterController: UIViewController? {
		guard let root = UIApplication.shared.keyWindow?.rootViewController else {
			return nil
		}
		var result = root
		while let presented = result.presentedViewController {
			result = presented
		}
		return result
	}

	private weak var presentedViewController: UIViewController?
	private var willResignActiveObserver: NSObjectProtocol?
	private var didBecomeActiveObserver: NSObjectProtocol?

	public static func activate() {
		SecureScreen.default.start()
	}

	public static func deactivate() {
		SecureScreen.default.stop()
	}

	private init() {}

	deinit {
		stop()
	}

	private func show() {
		guard
			let outterController = self.outterController,
			let controller = controllerToPresent() else {
				return
		}
		controller.modalPresentationStyle = .fullScreen
		outterController.present(controller, animated: false)
		self.presentedViewController = controller
	}

	private func hide() {
		guard let presented = presentedViewController, let presenting = presented.presentingViewController else {
			return
		}
		let controllers = presentedControllers(from: presented)
		presenting.dismiss(animated: false) {
			self.present(controllers, from: presenting)
		}
		self.presentedViewController = nil
	}

	private func start() {
		willResignActiveObserver = NotificationCenter.default.addObserver(forName: UIApplication.willResignActiveNotification, object: UIApplication.shared, queue: .main) { [unowned self] notification in
			self.show()
		}
		didBecomeActiveObserver = NotificationCenter.default.addObserver(forName: UIApplication.didBecomeActiveNotification, object: UIApplication.shared, queue: .main) { [unowned self] notification in
			self.hide()
		}
	}

	private func stop() {
		if let observer = willResignActiveObserver {
			NotificationCenter.default.removeObserver(observer)
		}
		if let observer = didBecomeActiveObserver {
			NotificationCenter.default.removeObserver(observer)
		}
	}

	private func controllerToPresent() -> UIViewController? {
		guard let storyboardName = Bundle.main.object(forInfoDictionaryKey: SecureScreen.storyboardNameKey) as? String else {
			return nil
		}
		let storyboard = UIStoryboard(name: storyboardName, bundle: nil)
		return storyboard.instantiateInitialViewController()
	}

	private func present(_ controllers: [UIViewController], from presenting: UIViewController) {
		guard let toPresent = controllers.first else { return }
		presenting.present(toPresent, animated: false) {
			self.present(Array(controllers.dropFirst()), from: toPresent)
		}
	}

	private func presentedControllers(from preseting: UIViewController) -> [UIViewController] {
		var result = [UIViewController]()
		var current = preseting
		while let controller = current.presentedViewController {
			result.append(controller)
			current = controller
		}
		return result
	}
}
