#!/usr/bin/env python
# Copyright (C) 2015 Splunk Inc. All Rights Reserved.
# Linear Holt-Winters forecast with online learning of parameters.

import math


def hw_linear_online(x, alpha=0.75, beta=0.25, gamma=1e-2, C=0.):  # C = 0.01
    """Compute one-ahead forecast using linear Holt-Winters model, with
    alpha and beta optimized to minimize prediction error.

    The "linear" Holt-Winters model is essentially just double
    exponential smoothing [3]. A one-ahead forecast is made by
    projecting the current estimate of the trend forward one step:

        s_next = alpha * x[t] + (1-alpha) * (s + b)
        b_next = beta * (s_next - s) + (1 - beta) * b
        x_hat[t+1] = s_next + b_next

    This implementation adjusts alpha and beta using stochastic
    gradient descent at each forecast step to minimize prediction
    error. The gradient is calculated analytically (dJda,dJdB) and
    L2-penalized (C). The learning rate (gamma) is adjusted using
    AdaGrad [1], which reduces the need for hand-tuning. The
    optimization problem is non-convex, so we alternate updates to
    alpha and beta [2].

    @param x: list of data values
    @param alpha: initial value for alpha
    @param beta: initial value for beta
    @param gamma: learning rate for gradient descent
    @param C: L2-regularization coefficient
    @returns (x_hat, alpha, beta) where
        x_hat: predicted data values, list of length len(x+1)
        alpha: final value of alpha
        beta: final value of beta

    [1] Duchi, John, Elad Hazan, and Yoram Singer. "Adaptive
    subgradient methods for online learning and stochastic
    optimization." The Journal of Machine Learning Research 12 (2011):
    2121-2159.
    [2] https://en.wikipedia.org/wiki/Non-linear_least_squares#Direct_search_methods
    [3] http://www.itl.nist.gov/div898/handbook/pmc/section4/pmc433.htm
    """
    x = [float(v) for v in x]
    x_hat = [0] * (len(x) + 1)

    H_alpha = 0.
    H_beta = 0.

    # Bootstrap
    s = x[1]
    b = x[1] - x[0]
    s_prev = 0
    b_prev = 0
    x_hat[2] = s + b

    for t in range(2, len(x)):
        if math.isnan(x[t]) or math.isnan(x[t - 1]):
            x_hat[t + 1] = s + b
            continue

        s_next = alpha * x[t] + (1 - alpha) * (s + b)
        b_next = beta * (s_next - s) + (1 - beta) * b

        # Error of forecast from previous iteration
        E = x_hat[t] - x[t]

        # Gradient w.r.t. alpha and beta
        dJda = E * (x[t - 1] - s_prev - b_prev)
        dJdB = E * (s - s_prev - b_prev)

        # AdaGrad update
        H_alpha += abs(dJda)
        H_beta += abs(dJdB)
        dJda = dJda / (1e-6 + pow(H_alpha, 1))
        dJdB = dJdB / (1e-6 + pow(H_beta, 1))
        H_alpha *= 0.99
        H_beta *= 0.99

        # Alternate updates to alpha and beta
        if t % 2:
            alpha_next = alpha - gamma * (dJda + C * alpha)
            beta_next = beta
        else:
            alpha_next = alpha
            beta_next = beta - gamma * (dJdB + C * beta)

        # Clamp alpha and beta to [0,1]
        # TODO: Shrink alpha/beta towards initial values?
        alpha = min(1., max(0., alpha_next))
        beta = min(1., max(0., beta_next))

        s = s_next
        b = b_next

        x_hat[t + 1] = s + b

    return x_hat, alpha, beta
