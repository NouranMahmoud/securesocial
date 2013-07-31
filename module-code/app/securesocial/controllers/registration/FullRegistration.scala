package securesocial.controllers.registration

import play.api.mvc.{ Result, Action, Controller }
import play.api.mvc.Results._
import play.api.data._
import play.api.data.Forms._
import play.api.data.validation.Constraints._
import play.api.{ Play, Logger }
import securesocial.core.providers.UsernamePasswordProvider
import securesocial.core._
import com.typesafe.plugin._
import Play.current
import securesocial.core.providers.utils._
import org.joda.time.DateTime
import play.api.i18n.Messages
import securesocial.core.providers.Token
import scala.Some
import securesocial.core.UserId
import securesocial.controllers.TemplatesPlugin
import securesocial.controllers.ProviderController
import securesocial.controllers.ProviderController.landingUrl

object FullRegistration extends Controller with securesocial.core.SecureSocial {
  import DefaultRegistration.{
    RegistrationInfo,
    UserName,
    UserNameAlreadyTaken,
    providerId,
    FirstName,
    LastName,
    Password,
    Password1,
    Password2,
    PasswordsDoNotMatch,
    Email,
    Success,
    SignUpDone,
    onHandleStartSignUpGoTo,
    ThankYouCheckEmail,
    TokenDurationKey,
    DefaultDuration,
    TokenDuration,
    createToken,
    executeForToken
  }

  val NotActive = "NotActive"

  case class FullRegistrationInfo(userName: Option[String], firstName: String, lastName: String, email: String, password: String)

  val formWithUsername = Form[FullRegistrationInfo](
    mapping(
      UserName -> nonEmptyText.verifying(Messages(UserNameAlreadyTaken), userName => {
        UserService.find(UserId(userName, providerId)).isEmpty
      }),
      FirstName -> nonEmptyText,
      LastName -> nonEmptyText,
      Email -> email.verifying(nonEmpty),
      (Password ->
        tuple(
          Password1 -> nonEmptyText.verifying(use[PasswordValidator].errorMessage,
            p => use[PasswordValidator].isValid(p)),
          Password2 -> nonEmptyText).verifying(Messages(PasswordsDoNotMatch), passwords => passwords._1 == passwords._2))) // binding
          ((userName, firstName, lastName, email, password) => FullRegistrationInfo(Some(userName), firstName, lastName, email, password._1)) // unbinding
          (info => Some(info.userName.getOrElse(""), info.firstName, info.lastName, info.email, ("", ""))))

  val formWithoutUsername = Form[FullRegistrationInfo](
    mapping(
      FirstName -> nonEmptyText,
      LastName -> nonEmptyText,
      Email -> email.verifying(nonEmpty),
      (Password ->
        tuple(
          Password1 -> nonEmptyText.verifying(use[PasswordValidator].errorMessage,
            p => use[PasswordValidator].isValid(p)),
          Password2 -> nonEmptyText).verifying(Messages(PasswordsDoNotMatch), passwords => passwords._1 == passwords._2))) // binding
          ((firstName, lastName, email, password) => FullRegistrationInfo(None, firstName, lastName, email, password._1)) // unbinding
          (info => Some(info.firstName, info.lastName, info.email, ("", ""))))

  val form = if (UsernamePasswordProvider.withUserNameSupport) formWithUsername else formWithoutUsername

  def signUp = Action { implicit request =>
    if (Logger.isDebugEnabled) {
      Logger.debug("[securesocial] trying sign up")
    }
    Ok(use[TemplatesPlugin].getFullSignUpPage(request, form))
  }

  /**
   * Handles posts from the sign up page
   */

  def handleSignUp = Action { implicit request =>
    form.bindFromRequest.fold(
      errors => {
        if (Logger.isDebugEnabled) {
          Logger.debug("[securesocial] errors " + errors)
        }
        BadRequest(use[TemplatesPlugin].getFullSignUpPage(request, errors))
      },
      info => {
        val id = info.email
        val userId = UserId(id, providerId)
        // check if there is already an account for this email address
        UserService.findByEmailAndProvider(info.email, UsernamePasswordProvider.UsernamePassword) match {
          case Some(user) => {
            // user signed up already, send an email offering to login/recover password
            Mailer.sendAlreadyRegisteredEmail(user)
          }
          case None => {
            val token = createToken(info.email, isSignUp = true)
            Mailer.sendVerificationEmail(info.email, token._1)

            val user = SocialUser(
              userId,
              info.firstName,
              info.lastName,
              "%s %s".format(info.firstName, info.lastName),
              NotActive,
              Some(info.email),
              GravatarHelper.avatarFor(info.email),
              AuthenticationMethod.UserPassword,
              passwordInfo = Some(Registry.hashers.currentHasher.hash(info.password)))
            val saved = UserService.save(user)

          }
        }
        Redirect(onHandleStartSignUpGoTo).flashing(Success -> Messages(ThankYouCheckEmail), Email -> info.email)
      })
  }
  //[ ] Create Verification action, it should check the token, if it is correct: set user state = active [@nouranmahmoud]
  def userVerification(token: String) = UserAwareAction { implicit request =>

    executeForToken(token, true, { t =>
      val email = t.email
      val providerId = t.uuid
      val userFromUrl = UserService.findByEmailAndProvider(email, UsernamePasswordProvider.UsernamePassword)
      userFromUrl match {
        case Some(userFromUrl) => request.user match {
          case Some(user) if (userFromUrl == user) =>
            val updated = UserService.save(SocialUser(userFromUrl).copy(state = "Active"))
            Mailer.sendWelcomeEmail(updated)
            val eventSession = Events.fire(new SignUpEvent(updated)).getOrElse(session)
            ProviderController.completeAuthentication(updated, eventSession).flashing(Success -> Messages(SignUpDone))
            Redirect(landingUrl)
          case _ =>
            UserService.save(SocialUser(userFromUrl).copy(state = "Active"))
            Redirect(RoutesHelper.login().url)

        }
        case _ => Unauthorized("Not Authorized Page")
      }
    })
  }
  
}