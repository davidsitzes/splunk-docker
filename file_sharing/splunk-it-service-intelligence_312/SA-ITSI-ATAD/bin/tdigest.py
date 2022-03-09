# The MIT License (MIT)

# Copyright (c) 2015 Cameron Davidson-Pilon

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import print_function

from random import shuffle, choice
import bintree
import json


class Centroid(object):

    def __init__(self, mean, count):
        self.mean = float(mean)
        self.count = float(count)

    def __repr__(self):
        return """<Centroid: mean=%.8f, count=%d>""" % (self.mean, self.count)

    def __eq__(self, other):
        return self.mean == other.mean and self.count == other.count

    def update(self, x, weight):
        self.count += weight
        self.mean += weight * (x - self.mean) / self.count
        return


class TDigest(object):

    def __init__(self, delta=0.01, K=25, json_str=None):
        self.C = bintree.BinaryTree()
        self.n = 0
        self.delta = delta
        self.K = K
        if json_str is not None:
            D = json.loads(json_str)
            self.n = D['n']
            self.delta = D['delta']
            self.K = D['K']
            self.C = bintree.BinaryTree()
            for pair in D['centroids']:
                centroid = Centroid(pair[0], pair[1])
                self.C.insert(centroid.mean, centroid)

    def __add__(self, other_digest):
        C1 = list(self.C.values())
        C2 = list(other_digest.C.values())
        shuffle(C1)
        shuffle(C2)
        data = C1 + C2
        new_digest = TDigest(self.delta, self.K)

        for c in data:
            new_digest.update(c.mean, c.count)

        return new_digest

    def __len__(self):
        return len(self.C)

    def __repr__(self):
        return """<T-Digest: n=%d, centroids=%d>""" % (self.n, len(self))

    def _add_centroid(self, centroid):
        if centroid.mean not in self.C:
            self.C.insert(centroid.mean, centroid)
        else:
            self.C[centroid.mean].update(centroid.mean, centroid.count)

    def _compute_centroid_quantile(self, centroid):
        denom = self.n
        cumulative_sum = sum(
            c_i.count for c_i in self.C.value_slice(-float('Inf'), centroid.mean))
        return (centroid.count / 2. + cumulative_sum) / denom

    def _update_centroid(self, centroid, x, w):
        self.C.pop(centroid.mean)
        centroid.update(x, w)
        self._add_centroid(centroid)

    def _find_closest_centroids(self, x):
        try:
            ceil_key = self.C.ceiling_key(x)
        except KeyError:
            floor_key = self.C.floor_key(x)
            return [self.C[floor_key]]

        try:
            floor_key = self.C.floor_key(x)
        except KeyError:
            ceil_key = self.C.ceiling_key(x)
            return [self.C[ceil_key]]

        if abs(floor_key - x) < abs(ceil_key - x):
            return [self.C[floor_key]]
        elif abs(floor_key - x) == abs(ceil_key - x) and (ceil_key != floor_key):
            return [self.C[ceil_key], self.C[floor_key]]
        else:
            return [self.C[ceil_key]]

    def _theshold(self, q):
        return 4 * self.n * self.delta * q * (1 - q)

    def update(self, x, w=1):
        """
        Update with value x and weight w.
        """
        self.n += w

        if len(self) == 0:
            self._add_centroid(Centroid(x, w))
            return

        S = self._find_closest_centroids(x)

        while len(S) != 0 and w > 0:
            j = choice(list(range(len(S))))
            c_j = S[j]

            q = self._compute_centroid_quantile(c_j)

            # This filters the out centroids that do not satisfy the second part
            # of the definition of S. See original paper by Dunning.
            if c_j.count + w > self._theshold(q):
                S.pop(j)
                continue

            delta_w = min(self._theshold(q) - c_j.count, w)
            self._update_centroid(c_j, x, delta_w)
            w -= delta_w
            S.pop(j)

        if w > 0:
            self._add_centroid(Centroid(x, w))

        if len(self) > self.K / self.delta:
            self.compress()

        return

    def batch_update(self, values, w=1):
        """
        Update with an iterable of values. All points have equal weight.
        """
        for x in values:
            self.update(x, w)

        self.compress()
        return

    def compress(self):
        T = TDigest(self.delta, self.K)
        C = list(self.C.values())
        shuffle(C)

        for c_i in C:
            T.update(c_i.mean, c_i.count)

        self.C = T.C

    def percentile(self, q):
        """
        Computes the percentile of a value in [0,1]: CDF^-1(q)
        """
        if not (0 <= q <= 1):
            raise ValueError("q must be between 0 and 1, inclusive.")

        t = 0
        q *= self.n

        for i, key in enumerate(self.C.keys()):
            c_i = self.C[key]
            k = c_i.count
            if q < t + k:
                if i == 0:
                    return c_i.mean
                elif i == len(self) - 1:
                    return c_i.mean
                else:
                    delta = (
                        self.C.succ_item(key)[1].mean - self.C.prev_item(key)[1].mean) / 2.
                return c_i.mean + ((q - t) / k - 0.5) * delta

            t += k
        return self.C.max_item()[1].mean

    def quantile(self, q):
        """
        Computes the quantile of a value: CDF(q)
        """
        t = 0
        N = float(self.n)

        for i, key in enumerate(self.C.keys()):
            c_i = self.C[key]
            if i == len(self) - 1:
                delta = (c_i.mean - self.C.prev_item(key)[1].mean) / 2.
            else:
                delta = (self.C.succ_item(key)[1].mean - c_i.mean) / 2.
            z = max(-1, (q - c_i.mean) / delta)

            if z < 1:
                return t / N + c_i.count / N * (z + 1) / 2

            t += c_i.count
        return 1

    def get_json(self):
        '''
        Returns a json string representation of the tdigest.
        '''
        D = dict()
        D['centroids'] = [(c.mean, c.count) for c in self.C.values()]
        D['n'] = self.n
        D['delta'] = self.delta
        D['K'] = self.K
        return json.dumps(D)
