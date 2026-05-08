// Copyright (c) 2018 Chandan B N. All rights reserved.
/* jshint esversion: 6 */
/* jshint browser:true */

var feedbackStartDelay = 250;
var feedbackTimeout = 20000;
var feedbackTimeoutText = 'Error. Try again.';

function feedback(element, type, text) {
    this.element = element;
    this.type = type;
    this.text = text;
    this.originalText = element ? element.textContent : '';
    this.feedbackTimer = null;
    this.errorTimer = null;
    this.started = false;
    this.spinnerHolder = null;
    this.errorHolder = null;
    this.addedOverlayClass = false;
    this.addedMinHeightClass = false;
    this.cancelled = false;
    this.isButton = !!(element && element.tagName == 'BUTTON');
    this.originalDisabled = this.isButton ? element.disabled : false;

    if (!this.element) {
        return;
    }

    if (this.isButton) {
        this.element.disabled = true;
    }

    var self = this;
    this.feedbackTimer = setTimeout(function () {
        self.feedbackTimer = null;
        self.start();
    }, feedbackStartDelay);

    this.errorTimer = setTimeout(function () {
        self.errorTimer = null;
        self.showError();
    }, feedbackTimeout);
}

feedback.prototype.start = function () {
    if (!this.element || this.cancelled || this.started) {
        return;
    }
    this.started = true;

    if (this.type === 'spinner') {
        this.showSpinner();
        return;
    }

    if (this.type === 'text') {
        this.element.textContent = this.text || '';
    }
};

feedback.prototype.showSpinner = function () {
    if (!this.element || this.spinnerHolder) {
        return;
    }

    this.removeSpinnerOrError();
    if (!this.element.classList.contains('feedback-overlay-target')) {
        this.element.classList.add('feedback-overlay-target');
        this.addedOverlayClass = true;
    }

    // Ensure there is enough vertical space for centering even when target is empty.
    var hasBounds = this.element.getBoundingClientRect ? this.element.getBoundingClientRect() : null;
    var minHeight = hasBounds ? hasBounds.height : 0;
    if (minHeight < 140 && !this.element.classList.contains('feedback-overlay-target--minheight')) {
        this.element.classList.add('feedback-overlay-target--minheight');
        this.addedMinHeightClass = true;
    }

    var holder = document.createElement('div');
    holder.className = 'feedback-spinner-holder';

    var spinner = document.createElement('div');
    spinner.className = 'spinner feedback-spinner';
    holder.appendChild(spinner);
    this.element.appendChild(holder);
    this.spinnerHolder = holder;
};

feedback.prototype.showError = function () {
    if (!this.element || this.cancelled) {
        return;
    }

    this.start();

    if (this.type === 'spinner') {
        this.removeSpinnerOrError();
        var holder = document.createElement('div');
        holder.className = 'feedback-error-holder';
        holder.textContent = feedbackTimeoutText;
        this.element.appendChild(holder);
        this.errorHolder = holder;
        return;
    }

    if (this.type === 'text') {
        this.element.textContent = feedbackTimeoutText;
    }
};

feedback.prototype.removeSpinnerOrError = function () {
    if (this.spinnerHolder && this.spinnerHolder.parentNode) {
        this.spinnerHolder.parentNode.removeChild(this.spinnerHolder);
    }
    this.spinnerHolder = null;

    if (this.errorHolder && this.errorHolder.parentNode) {
        this.errorHolder.parentNode.removeChild(this.errorHolder);
    }
    this.errorHolder = null;
};

feedback.prototype.cancel = function () {
    this.cancelled = true;

    if (this.feedbackTimer) {
        clearTimeout(this.feedbackTimer);
        this.feedbackTimer = null;
    }

    if (this.errorTimer) {
        clearTimeout(this.errorTimer);
        this.errorTimer = null;
    }

    if (!this.element) {
        return;
    }

    if (this.type === 'spinner') {
        this.removeSpinnerOrError();
        if (this.addedOverlayClass) {
            this.element.classList.remove('feedback-overlay-target');
            this.addedOverlayClass = false;
        }
        if (this.addedMinHeightClass) {
            this.element.classList.remove('feedback-overlay-target--minheight');
            this.addedMinHeightClass = false;
        }
    } else if (this.type === 'text') {
        this.element.textContent = this.originalText;
    }

    if (this.isButton) {
        this.element.disabled = this.originalDisabled;
    }
};

if (typeof window !== 'undefined') {
    window.feedback = feedback;
}

export {
    feedback
};
