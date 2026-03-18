# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'connect_info.ui'
##
## Created by: Qt User Interface Compiler version 6.10.1
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QLabel,
    QPushButton, QSizePolicy, QSpacerItem, QVBoxLayout,
    QWidget)
class Ui_ConnectInfoForm(object):
    def setupUi(self, ConnectInfoForm):
        if not ConnectInfoForm.objectName():
            ConnectInfoForm.setObjectName(u"ConnectInfoForm")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(ConnectInfoForm.sizePolicy().hasHeightForWidth())
        ConnectInfoForm.setSizePolicy(sizePolicy)
        self.verticalLayout_ci = QVBoxLayout(ConnectInfoForm)
        self.verticalLayout_ci.setSpacing(0)
        self.verticalLayout_ci.setObjectName(u"verticalLayout_ci")
        self.verticalLayout_ci.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_4 = QHBoxLayout()
        self.horizontalLayout_4.setSpacing(0)
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.horizontalSpacer_2 = QSpacerItem(0, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_4.addItem(self.horizontalSpacer_2)

        self.initStepsImage = QLabel(ConnectInfoForm)
        self.initStepsImage.setObjectName(u"initStepsImage")
        self.initStepsImage.setMinimumSize(QSize(0, 0))
        self.initStepsImage.setMaximumSize(QSize(685, 260))
        self.initStepsImage.setFrameShape(QFrame.Shape.NoFrame)
        self.initStepsImage.setPixmap(QPixmap(u"images/initsteps.png"))
        self.initStepsImage.setScaledContents(True)
        self.initStepsImage.setAlignment(Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignTop)
        self.initStepsImage.setWordWrap(False)
        self.initStepsImage.setMargin(0)

        self.horizontalLayout_4.addWidget(self.initStepsImage)

        self.horizontalSpacer = QSpacerItem(0, 18, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_4.addItem(self.horizontalSpacer)


        self.verticalLayout_ci.addLayout(self.horizontalLayout_4)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.horizontalSpacer_6 = QSpacerItem(10, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_6)

        self.label_2 = QLabel(ConnectInfoForm)
        self.label_2.setObjectName(u"label_2")
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy1)
        self.label_2.setMinimumSize(QSize(195, 0))
        self.label_2.setMaximumSize(QSize(195, 16777215))
        self.label_2.setAlignment(Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignTop)
        self.label_2.setWordWrap(True)
        self.label_2.setMargin(5)

        self.horizontalLayout_3.addWidget(self.label_2)

        self.horizontalSpacer_3 = QSpacerItem(50, 0, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_3)

        self.label_3 = QLabel(ConnectInfoForm)
        self.label_3.setObjectName(u"label_3")
        sizePolicy1.setHeightForWidth(self.label_3.sizePolicy().hasHeightForWidth())
        self.label_3.setSizePolicy(sizePolicy1)
        self.label_3.setMinimumSize(QSize(195, 10))
        self.label_3.setMaximumSize(QSize(195, 16777215))
        self.label_3.setAlignment(Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignTop)
        self.label_3.setWordWrap(True)
        self.label_3.setMargin(5)

        self.horizontalLayout_3.addWidget(self.label_3)

        self.horizontalSpacer_4 = QSpacerItem(50, 0, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_4)

        self.label_4 = QLabel(ConnectInfoForm)
        self.label_4.setObjectName(u"label_4")
        sizePolicy1.setHeightForWidth(self.label_4.sizePolicy().hasHeightForWidth())
        self.label_4.setSizePolicy(sizePolicy1)
        self.label_4.setMinimumSize(QSize(195, 0))
        self.label_4.setMaximumSize(QSize(195, 16777215))
        self.label_4.setScaledContents(False)
        self.label_4.setAlignment(Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignTop)
        self.label_4.setWordWrap(True)
        self.label_4.setMargin(5)

        self.horizontalLayout_3.addWidget(self.label_4)

        self.horizontalSpacer_5 = QSpacerItem(10, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_5)


        self.verticalLayout_ci.addLayout(self.horizontalLayout_3)

        self.horizontalLayout_5 = QHBoxLayout()
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.horizontalSpacer_showdebug = QSpacerItem(50, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_5.addItem(self.horizontalSpacer_showdebug)

        self.showdebugbtn = QPushButton(ConnectInfoForm)
        self.showdebugbtn.setObjectName(u"showdebugbtn")

        self.horizontalLayout_5.addWidget(self.showdebugbtn)


        self.verticalLayout_ci.addLayout(self.horizontalLayout_5)


        self.retranslateUi(ConnectInfoForm)

        QMetaObject.connectSlotsByName(ConnectInfoForm)
    # setupUi

    def retranslateUi(self, ConnectInfoForm):
        self.label_2.setText(QCoreApplication.translate("ConnectInfoForm", u"<html><head/><body><p><span style=\" font-weight:600;\">Step 1:</span></p><p>Power off the phone</p></body></html>", None))
        self.label_3.setText(QCoreApplication.translate("ConnectInfoForm", u"<html><head/><body><p><span style=\" font-weight:600;\">Step 2:</span></p><p>Connect the USB cable, hold both volume buttons if needed</p></body></html>", None))
        self.label_4.setText(QCoreApplication.translate("ConnectInfoForm", u"<html><head/><body><p>No connection? Try shorting the test point to ground</p></body></html>", None))
        self.showdebugbtn.setText(QCoreApplication.translate("ConnectInfoForm", u"Show Debug Log", None))
        pass
    # retranslateUi

